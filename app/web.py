from flask import Flask, request, session, current_app, redirect, abort, Response, stream_with_context
from urllib.parse import quote as uriencode
from datetime import datetime, timedelta
import requests
from uuid import uuid4
import json
import base64
import logging
import pickle

app = Flask(__name__)

def redirect_uri():
   return (current_app.config['REDIRECT_URI'] if 'REDIRECT_URI' in current_app.config else request.host_url) + \
          (current_app.config['PREFIX'] if 'PREFIX' in current_app.config else '') + \
          '::authenticated::'

def set_state():
   state = str(uuid4())
   session['state'] = state
   return state

def set_nonce():
   nonce = str(uuid4())
   return nonce

def auth_uri():
   dest_uri = redirect_uri()
   state = set_state()
   nonce = set_nonce()
   session['state.path'] = request.path
   session['state.args'] = pickle.dumps(request.args)
   return current_app.config['AUTH_PROVIDER'] + '?' + \
      'client_id=' + current_app.config['CLIENT_ID'] + \
      '&response_type=code' + \
      '&scope=openid%20email' + \
      '&redirect_uri='+uriencode(dest_uri) + \
      '&state='+state + \
      '&nonce='+nonce

def exchange_code(code):
   logger = logging.getLogger(__name__)
   data = {
      'code' : code,
      'client_id' : current_app.config['CLIENT_ID'],
      'client_secret' : current_app.config['CLIENT_SECRET'],
      'redirect_uri' : redirect_uri(),
      'grant_type' : 'authorization_code'
   }

   if logger.isEnabledFor(logging.DEBUG):
      logger.debug('Exchanging code {code} for {redirect_uri}'.format(**data))

   exchange_req = requests.post(current_app.config['TOKEN_PROVIDER'],data)

   if exchange_req.status_code==200:
      if logger.isEnabledFor(logging.DEBUG):
         logger.debug('Code exchanged successfully.')
      return exchange_req.json()
   else:
      if logger.isEnabledFor(logging.DEBUG):
         logger.debug('Cannot exchange code, {status} {response}'.format(status=exchange_req.status_code,response=exchange_req.text))
      abort(401)

def get_principal(token):
   parts = token.split('.')

   user = json.loads(base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8'))

   return user.get('email')

@app.before_request
def before_request():

   logger = logging.getLogger(__name__)
   authenticated = 'token' in session and session['token'] is not None

   # check expiry
   if authenticated:
      if 'expiry' in session:
         elapsed = session['expiry'] - datetime.now()
         if elapsed.total_seconds()<0:
            logger.debug('Session expired.')
            authenticated = False
            session.pop('token',None)
            session.pop('expiry',None)
      else:
         authenticated = False
         logger.debug('No session expiry.')
         session.pop('token',None)

   if authenticated or request.path=='/::authenticated::':
      return

   logger.debug('Not authenticated, redirecting to auth provider.')

   return redirect(auth_uri())

@app.route('/::authenticated::',methods=['GET'])
def authenticated():
   logger = logging.getLogger(__name__)
   if request.args.get('state','')!=session.get('state'):
      logger.warning('Unauthroized, session "{session_state}" did not match state "{state}".'.format(session_state=session.get('state'),state=request.args.get('state','')))
      abort(401)
   session.pop('state',None)

   info = exchange_code(request.args.get('code',''))

   token = info['id_token']

   if logger.isEnabledFor(logging.DEBUG):
      logger.debug('Code exchanged for token {token}'.format(token=token))

   if 'WHITELIST' in current_app.config:
      principal = get_principal(token)
      if principal not in current_app.config['WHITELIST']:
         logger.warning('Unauthorized, {user} not in whitelist.'.format(user=principal))
         abort(401)

   expiry = datetime.now() + timedelta(seconds=info['expires_in'])
   if logger.isEnabledFor(logging.DEBUG):
      logger.debug('Token {token} expires in {expiry}'.format(token=token,expiry=expiry.isoformat()))
   session['token'] = token
   session['expiry'] = expiry
   path = session.pop('state.path','/')
   prefix = current_app.config['PREFIX'] if 'PREFIX' in current_app.config else ''
   if len(prefix)>0 and prefix[-1]=='/':
      prefix = prefix[0:-1]
   args = (lambda x : pickle.loads(x) if x is not None else {})(session.pop('state.args',None))
   for index,name in enumerate(args):
      path = path + ('?' if index==0 else '&') + name + '=' + uriencode(args[name])
   return redirect(prefix+path)

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
   if lastModified is not None:
      response_headers.pop('Last-Modified',None)
      response_headers['Last-Modified'] = unquote_plus(lastModified)
   data = req.iter_content(chunk_size=1024*32)

   response = Response(stream_with_context(data), headers=response_headers)
   response.status_code = req.status_code;
   return response
