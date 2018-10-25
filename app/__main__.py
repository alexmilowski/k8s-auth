import os
import sys
import argparse
import base64
from app.web import app
from flask_session import Session

parser = argparse.ArgumentParser(description='Authetication proxy for k8s')
parser.add_argument('client_id',help='The client id for the authentication provider.')
parser.add_argument('client_secret',help='The client secret for the authentication provider.')
parser.add_argument('--redirect-uri',help='The redirect uri to use for this service.')
parser.add_argument('--endpoint',help='The endpoint of the service being proxied.',default='http://localhost:5000/')
parser.add_argument('--auth-provider',help='The endpoint of the service being proxied.',default='https://accounts.google.com/o/oauth2/v2/auth')
parser.add_argument('--token-provider',help='The endpoint of the service being proxied.',default='https://www.googleapis.com/oauth2/v4/token')
parser.add_argument('--session-key',help='The flask session key secrete (base64 encoded - e.g., base64.b64encode(os.urandom(24)))')
parser.add_argument('--session-redis',help='The redis server for shared sessions')
parser.add_argument('--debug',help='The flask session key',default=False,action='store_true')
parser.add_argument('--no-verify-endpoint',default=False,action='store_true',help='Disables SSL key verification for endpoint')
parser.add_argument('--whitelist',help='A whitelist of principals to allow.')
parser.add_argument('--allow',help='A principal to allow.',action='append')

args = parser.parse_args()

if args.session_key is None:
   args.session_key = os.urandom(24)
else:
   # Example
   # base64.b64encode(os.urandom(24))
   args.session_key = base64.b64decode(args.session_key)

app.secret_key = args.session_key
app.config['CLIENT_ID'] = args.client_id
app.config['CLIENT_SECRET'] = args.client_secret
if args.redirect_uri is not None:
   app.config['REDIRECT_URI'] = args.redirect_uri
app.config['ENDPOINT'] = args.endpoint
app.config['AUTH_PROVIDER'] = args.auth_provider
app.config['TOKEN_PROVIDER'] = args.token_provider
app.config['DEBUG'] = args.debug
app.config['VERIFY'] = True if not args.no_verify_endpoint else False

if args.session_redis is not None:
   import redis
   parts = args.session_redis.split(':')
   if len(parts)>1:
      hostname = parts[0]
      port = int(parts[1])
   else:
      hostname = parts[0]
      port = 6379
   app.config['SESSION_TYPE'] = 'redis'
   app.config['SESSION_REDIS'] = redis.Redis(host=hostname,port=port)

if args.whitelist is not None:
   import json
   with open(args.whitelist,'r') as data:
      whitelist = json.load(data)
      if type(whitelist)!=list:
         raise ValueError('Whist list must be a JSON array.')
      app.config['WHITELIST'] = whitelist

if args.allow is not None:
   whitelist = app.config.get('WHITELIST')
   if whitelist is None:
      whitelist = []
      app.config['WHITELIST'] = whitelist

   whitelist.extend(args.allow)

Session(app)

if __name__ == '__main__':
   app.run('0.0.0.0')
