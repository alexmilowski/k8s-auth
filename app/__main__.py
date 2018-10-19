import os
import sys
from app.web import app

client_id = None
client_secret = None
redirect_uri = 'http://localhost:5000/'
endpoint = 'http://localhost:5000/'
auth_provider = 'https://accounts.google.com/o/oauth2/v2/auth'
token_provider = 'https://www.googleapis.com/oauth2/v4/token'
if __name__ == '__main__':
   client_id = sys.argv[1] if len(sys.argv)>1 else client_id
   client_secret = sys.argv[2] if len(sys.argv)>2 else client_secret
   redirect_uri = sys.argv[3] if len(sys.argv)>3 else redirect_uri
   endpoint = sys.argv[4] if len(sys.argv)>4 else endpoint
   auth_provider = sys.argv[5] if len(sys.argv)>5 else auth_provider
   token_provider = sys.argv[6] if len(sys.argv)>6 else token_provider

key = os.environ.get('SECRET_KEY')
if key is None:
   key = os.urandom(16)
app.config['SECRET_KEY'] = key
app.config['CLIENT_ID'] = client_id
app.config['CLIENT_SECRET'] = client_secret
app.config['REDIRECT_URI'] = redirect_uri
app.config['ENDPOINT'] = endpoint
app.config['AUTH_PROVIDER'] = auth_provider
app.config['TOKEN_PROVIDER'] = token_provider
app.config['DEBUG'] = True

if __name__ == '__main__':
   app.run('0.0.0.0')
