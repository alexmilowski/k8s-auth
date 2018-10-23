from flask import Flask, request, session, current_app, redirect, abort, Response, stream_with_context
from urllib.parse import quote as uriencode
from datetime import datetime, timedelta
import requests
from uuid import uuid4
import os
import sys

app = Flask(__name__)

def redirect_uri():
   return current_app.config['REDIRECT_URI'] +'::authenticated::'

def set_state():
   state = str(uuid4())
   session['state'] = state
   return state

def set_nonce():
   nonce = str(uuid4())
   return nonce

def auth_uri():
   return current_app.config['AUTH_PROVIDER'] + '?' + \
      'client_id=' + current_app.config['CLIENT_ID'] + \
      '&response_type=code' + \
      '&scope=openid%20email' + \
      '&redirect_uri='+uriencode(redirect_uri()) + \
      '&state='+set_state() + \
      '&nonce='+set_nonce()

def exchange_code(code):
   data = {
      'code' : code,
      'client_id' : current_app.config['CLIENT_ID'],
      'client_secret' : current_app.config['CLIENT_SECRET'],
      'redirect_uri' : redirect_uri(),
      'grant_type' : 'authorization_code'
   }

   exchange_req = requests.post(current_app.config['TOKEN_PROVIDER'],data)

   if exchange_req.status_code==200:
      return exchange_req.json()
   else:
      print(exchange_req.status_code)
      abort(401)

@app.before_request
def before_request():
   authenticated = 'token' in session and session['token'] is not None

   # check expiry
   if authenticated:
      if 'expiry' in session:
         elapsed = session['expiry'] - datetime.now()
         if elapsed.total_seconds()<0:
            authenticated = False
            session.pop('token',None)
            session.pop('expiry',None)
      else:
         authenticated = False
         session.pop('token',None)

   if authenticated or request.path=='/::authenticated::':
      return

   return redirect(auth_uri())

@app.route('/::authenticated::',methods=['GET'])
def authenticated():
   print(session)
   if request.args.get('state','')!=session.get('state'):
      print('Unauthroized, state did not match.')
      abort(401)
   session.pop('state',None)
   print(request.args)

   info = exchange_code(request.args.get('code',''))
   print(info)
   expiry = datetime.now() + timedelta(seconds=info['expires_in'])
   session['token'] = info['id_token']
   session['expiry'] = expiry
   return redirect('/')

@app.route('/',methods=['GET','POST','PUT','DELETE'])
def index():
   return proxy('')

@app.route('/<path:path>',methods=['GET','POST','PUT','DELETE'])
def proxy(path):
   proxy_headers = {}
   for entry in request.headers:
      if entry[0] != 'Host' and \
         entry[0] != 'Authorization':
         proxy_headers[entry[0]] = entry[1]

   if 'token' in session:
      proxy_headers['Authorization'] = 'Bearer ' + session['token']

   service = current_app.config['ENDPOINT']
   url = service + path
   req = requests.request(
      request.method,
      url,
      data=request.data if request.method in ['POST','PUT'] else None,
      stream=True,
      params=request.args,
      cookies=request.cookies,
      proxies=app.config['PROXIES'] if 'PROXIES' in app.config else None,
      headers=proxy_headers,
      allow_redirects=False,
      verify=app.config['VERIFY'] if 'VERIFY' in app.config else True)
   response_headers = dict(req.headers)
   location = response_headers.get('Location')
   if location is not None and location[0:len(service)]==service:
      response_headers['Location'] = location[len(service):]
   response_headers.pop('Server',None)
   response_headers.pop('Date',None)
   response_headers.pop('Transfer-Encoding',None)
   response_headers.pop('Content-Length',None)
   lastModified = response_headers.get('Last-Modified')
   # Because some KNOX / Hadoop things are really broken
   if lastModified is not None:
      response_headers.pop('Last-Modified',None)
      response_headers['Last-Modified'] = unquote_plus(lastModified)
   # contentType = response_headers.get('Content-Type')
   # if contentType is not None and contentType[0:9]=='text/html':
   #
   #    semicolon = contentType.find(';')
   #    encoding = 'UTF-8'
   #    if semicolon>0:
   #       params = contentType[semicolon+1:]
   #       pos = params.find('charset=')
   #       value = params[pos+8:]
   #       semicolon = value.find(';')
   #       encoding = value[0:semicolon] if semicolon>0 else value
   #
   #    def textchunks():
   #       for chunk in iterdecode(req.iter_content(chunk_size=1024*32),encoding):
   #          yield chunk
   #    data = replaceuri(textchunks(),service,'/')
   # else:
   data = req.iter_content(chunk_size=1024*32)

   response = Response(stream_with_context(data), headers=response_headers)
   response.status_code = req.status_code;
   return response
