#!/usr/bin/env python3

import argparse
import sys
import os
import re
import requests
import hashlib
import json5 as json
from bs4 import BeautifulSoup
from ezprogress.progressbar import ProgressBar # multithread support
from threading import Thread, Lock
from queue import Queue
from dnslib import DNSRecord
from socket import (socket, setdefaulttimeout, gethostbyname,
                    timeout as SOCK_TIMEOUT,
                    AF_INET as IPV4,
                    SOCK_STREAM as TCP,
                    SOCK_DGRAM as UDP,
                    IPPROTO_TCP, IPPROTO_UDP)


class Eren(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Repo: https://www.gitlab.com/0xfederico/eren',
            usage='\n'.join(('python3 eren.py <command> [<args>]',
            '',
            'Available commands:',
            '   subdomain_fuzzing     search for subdomains starting from a wordlist (already included in the repo)',
            '   injection             test of the most famous injections on http GET/POST methods starting from a URL',
            '   ports_scan            multithreading scan all ports (not very useful, it is for educational purposes only)'))
        )

        self.parser.add_argument('command', help='subcommand to run')

        # check if the command was passed in input
        if len(sys.argv) == 1:
            print(f'[E] you need to specify the command\n')
            self.parser.print_help()
            exit(1)
        else:
            args = self.parser.parse_args(sys.argv[1:2])

        # check if the command passed in input exists
        if not hasattr(self, args.command):
            print(f'[E] command "{args.command}" not recognized\n')
            self.parser.print_help()
            exit(1)
        else:
            getattr(self, args.command)() # exec the function with the same name of command

    ###########################################################################################################################################

    def subdomain_fuzzing(self):
        results = []
        current_step = 0 # progress bar
        queue = Queue()
        lock = Lock()

        parser = argparse.ArgumentParser(
            description='Description: search for subdomains starting from a wordlist (already included in the repo)',
            usage='\n'.join(('python3 eren.py subdomain_fuzzing [<args>]',
            '',
            'Available arguments:',
            '   target                domain on which subdomains will be searched',
            '   wordlist              absolute path of the wordlist to use (the default is already present in the repo)',
            '   threads               the number of threads to use (default 100)',
            '   kdomains              list of already known domains (e.g. "www.google.com" for target google.com)'))
        )
        parser.add_argument('target')
        parser.add_argument('--wordlist', default=f'{os.path.join(os.path.dirname(os.path.abspath("__file__")), "data", "subdomains.txt")}')
        parser.add_argument('--threads', default='100')
        parser.add_argument('--kdomains', nargs='*')

        # check if the arguments was passed in input
        if len(sys.argv) == 2:
            print(f'[E] you need to specify the arguments\n')
            parser.print_help()
            exit(1)
        else:
            args = parser.parse_args(sys.argv[2:])
        
        kdomains_hashes = list()
        if args.kdomains is not None:
            for kd in args.kdomains:
                kdomains_hashes.append(
                    hashlib.sha512(str(requests.get(f'http://{kd}', headers = {'Host': f'{kd}'}).text).encode('utf-8')).hexdigest()
                )

        f = open(args.wordlist, 'r')
        subdomains = f.readlines()
        f.close()
        threads = int(args.threads)
        pb = ProgressBar(len(subdomains), bar_length=100, no_time=True)
        pb.start()

        def worker():
            nonlocal current_step,results # nonlocal because we are inside a function that is inside another function
            while not queue.empty():
                subd = queue.get()
                try:
                    # to see if a page is new compared to the others, the sha512 hash is calculated on the response to the HTTP GET request
                    r = hashlib.sha512(str(requests.get(f'http://{subd.strip()}.{args.target}', headers = {'Host': f'{subd.strip()}.{args.target}'}).text).encode('utf-8')).hexdigest()
                except (requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects):
                    lock.acquire()
                    current_step += 1
                    pb.update(current_step)
                    lock.release()
                else:
                    lock.acquire()
                    current_step += 1
                    pb.update(current_step)
                    if r not in kdomains_hashes:
                        results.append(f'[FOUND] LINE {i+1} --> http://{subd.strip()}.{args.target}')
                    lock.release()
                queue.task_done()

        for subd in subdomains:
            queue.put((subd))

        for i in range(threads):
            t = Thread(target=worker)
            t.start()

        queue.join()

        if results:
            print("\n".join(results))

    ###########################################################################################################################################

    def injection(self):
        parser = argparse.ArgumentParser(
            description='Description: test of the most famous injections on http GET/POST methods starting from a URL',
            usage='\n'.join(('python3 eren.py injection [<args>]',
            '',
            'Available arguments:',
            '   target                full URL of the page to be tested',
            '   method                HTTP GET or POST',
            '   parameter             HTTP GET/POST parameter name to be tested',
            '   selector              where do you expect to find the result (insert the CSS selector)'))
        )

        parser.add_argument('target')
        parser.add_argument('method', choices=['GET', 'POST'])
        parser.add_argument('parameter')
        parser.add_argument('selector')
        
        # check if the arguments was passed in input
        if len(sys.argv) == 2:
            print(f'[E] you need to specify the arguments\n')
            parser.print_help()
            exit(1)
        else:
            args = parser.parse_args(sys.argv[2:])

        infection_vectors_file = open(os.path.join(os.path.dirname(os.path.abspath("__file__")), "data", "injection_vectors.json"), 'r')
        infection_vectors = json.loads(infection_vectors_file.read())
        infection_vectors_file.close()

        for category in infection_vectors.keys():
            for name,elements in infection_vectors[category].items():
                for e in elements:
                    if args.method == 'GET':
                        response = requests.get(url=f"http://{args.target}", params={args.parameter:e['payload']}).text
                    if args.method == 'POST':
                        response = requests.post(url=f"http://{args.target}", data={args.parameter:e['payload']}).text
                    result = BeautifulSoup(response, 'html.parser').select(args.selector)
                    if len(result) > 0:
                        if e['expected_result'] in str(result[0]):
                            print(f"[FOUND] {category} -> {name} -> {e['expected_result']}")
    
    ###########################################################################################################################################

    def ports_scan(self):
        results = []
        current_step = 0 # progress bar
        queue = Queue()
        lock = Lock()
        
        parser = argparse.ArgumentParser(
            description='Description: multithreading scan all ports (not very useful, it is for educational purposes only)',
            usage='\n'.join(('python3 eren.py ports_scan [<args>]',
            '',
            'Available arguments:',
            '   target                IP address or domain on which to scan the ports',
            '   threads               the number of threads to use (default 100)',
            '   prange                range of ports to scan start-end (default: all ports))'))
        )
        parser.add_argument('target')
        parser.add_argument('--threads', default='100')
        parser.add_argument('--prange', default='1-65535')
        
        # check if the arguments was passed in input
        if len(sys.argv) == 2:
            print(f'[E] you need to specify the arguments\n')
            parser.print_help()
            exit(1)
        else:
            args = parser.parse_args(sys.argv[2:])

        target = args.target
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            target = gethostbyname(args.target)
        
        setdefaulttimeout(1.0)
        threads = int(args.threads)
        prange = range(int(args.prange.split('-')[0]), int(args.prange.split('-')[1])+1)
        pb = ProgressBar(len(prange), bar_length=100, no_time=True)
        pb.start()

        def check_port_open(target, port): 
            stdout = [] # save the output and return it -> it is not printed immediately so as not to break the progress bar

            # TCP
            client_tcp = socket(IPV4, TCP, IPPROTO_TCP)
            result = client_tcp.connect_ex((target, port))
            if result == 0:
                stdout.append(f'[TCP OPEN] target {target} - port {port}')

            # UDP
            client_udp = socket(IPV4, UDP, IPPROTO_UDP)
            try:
                client_udp.sendto('GET / HTTP/1.1'.encode('utf8'), (target, port))
                data, _ = client_udp.recvfrom(1024)
                if data:
                    stdout.append(f'[UDP OPEN] target {target} - port {port}')
            except SOCK_TIMEOUT:
                pass

            try:
                client_udp.sendto('ping'.encode('utf8'), (target, port))
                data, _ = client_udp.recvfrom(1024)
                if data:
                    stdout.append(f'[UDP OPEN] target {target} - port {port}')
            except SOCK_TIMEOUT:
                pass

            try:
                client_udp.sendto(bytes(DNSRecord.question("gitlab.com").pack()), (target, port)) # DNS is a binary protocol!
                data, _ = client_udp.recvfrom(1024)
                if data:
                    stdout.append(f'[UDP OPEN] target {target} - port {port}')
            except SOCK_TIMEOUT:
                pass
            
            client_tcp.close()
            client_udp.close()

            return list(set(stdout))

        def worker():
            nonlocal current_step,results # nonlocal because we are inside a function that is inside another function
            while not queue.empty():
                (target,port) = queue.get()
                stdout = check_port_open(target, port)
                lock.acquire()
                results += stdout
                current_step += 1
                pb.update(current_step)
                lock.release()
                queue.task_done()

        for port in prange:
            queue.put((target,port))

        for i in range(threads):
            t = Thread(target=worker)
            t.start()

        queue.join()

        extract_port = lambda x : int(x.split('-')[1].replace("port", "").strip())
        if results:
            print("\n".join(sorted(results, key=extract_port)))


if __name__ == '__main__':
    Eren() # TATAKAE!
