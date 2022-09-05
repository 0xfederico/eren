# CREDITS: https://github.com/epinna/tplmap#server-side-template-injection

from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
Jinja2 = Environment()

@app.route('/', methods = ['POST', 'GET'])
def home():
    if request.method == 'POST':
        test = request.form['test']
    if request.method == 'GET':
        test = request.values.get('test')
    
    if test is not None:
        # VULNERABLE VERSION
        return Jinja2.from_string('\n'.join((
            '<!DOCTYPE html>',
            '<html>',
            '<head>', '<title>Example injection page</title>', '</head>',
            '<body>', '<p>test: ' + test + '</p>', '</body>',
            '</html>'))).render()
        # SAFE VERSION
        # return Jinja2.from_string('\n'.join((
        #     '<!DOCTYPE html>',
        #     '<html>',
        #     '<head>', '<title>Example injection page</title>', '</head>',
        #     '<body>', '<p>test: {{test}}</p>', '</body>',
        #     '</html>'))).render(test = test)
    else:
        return Jinja2.from_string('\n'.join((
            '<!DOCTYPE html>',
            '<html>',
            '<head>', '<title>Example injection page</title>', '</head>',
            '<body>', '<h1>Example injection page</h1>', '<p>Please provide "test" parameter</p>', '</body>',
            '</html>'))).render()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)