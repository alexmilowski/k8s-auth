import os
import sys
import argparse
from app.web import app

parser = argparse.ArgumentParser(description='Authetication proxy for k8s')
parser.add_argument('client_id',help='The client id for the authentication provider.')
parser.add_argument('client_secret',help='The client secret for the authentication provider.')
parser.add_argument('--redirect-uri',help='The redirect uri to use for this service.',default='http://localhost:5000/')
parser.add_argument('--endpoint',help='The endpoint of the service being proxied.',default='http://localhost:5000/')
parser.add_argument('--auth-provider',help='The endpoint of the service being proxied.',default='https://accounts.google.com/o/oauth2/v2/auth')
parser.add_argument('--token-provider',help='The endpoint of the service being proxied.',default='https://www.googleapis.com/oauth2/v4/token')
parser.add_argument('--session-key',help='The flask session key')
parser.add_argument('--debug',help='The flask session key',default=False)
parser.add_argument('--no-verify-endpoint',default=False,action='store_true',help='Disables SSL key verification for endpoint')

args = parser.parse_args()

if args.session_key is None:
   args.session_key = os.urandom(16)
app.config['SECRET_KEY'] = args.session_key
app.config['CLIENT_ID'] = args.client_id
app.config['CLIENT_SECRET'] = args.client_secret
app.config['REDIRECT_URI'] = args.redirect_uri
app.config['ENDPOINT'] = args.endpoint
app.config['AUTH_PROVIDER'] = args.auth_provider
app.config['TOKEN_PROVIDER'] = args.token_provider
app.config['DEBUG'] = args.debug
app.config['VERIFY'] = True if not args.no_verify_endpoint else False

if __name__ == '__main__':
   app.run('0.0.0.0')
