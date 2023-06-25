import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from flask_sqlalchemy import SQLAlchemy

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "*********"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/youtube', 'https://www.googleapis.com/auth/youtube.readonly', 'openid', 'https://www.googleapis.com/auth/userinfo.email']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = flask.Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql:///youtube"
db = SQLAlchemy(app)


class SUBS(db.Model):
  __tablename__ = "subscribers"
  youtube_id = db.Column(db.String(255), primary_key=True)
  email_address = db.Column(db.String(255), nullable=False)
  num_referred = db.Column(db.Integer(), nullable=True)

  def __init__(self, youtube_id, email_address, num_referred):
    self.youtube_id = youtube_id
    self.email_address = email_address
    self.num_referred = num_referred

db.create_all()


@app.route('/')
def index():
  flask.session['source'] = 0 # flask session source:   0 -> base website, 1 -> from referral link
  return flask.render_template("index.html")


@app.route('/authorize')
def authorize():
  if 'source' not in flask.session:
  	return flask.redirect('/')
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)




@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  if flask.session['source'] == 0:
    return flask.redirect(flask.url_for('your_referral'))

  if flask.session['source'] == 1:
  	referrer_id = flask.session['referrer_id']
  	return flask.redirect('/referral/'+str(referrer_id))




@app.route('/your_referral')
def your_referral():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])


  email = (get_user_email(flask.session['credentials']['token'])['email']) #obtain user email

  youtube = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)


  #### checking if user is subscribed
  request = youtube.subscriptions().list(
        part="snippet,contentDetails",
        forChannelId="UC9BNjNQvbSRWzYrF51UzXyQ",
        mine=True
    )
  response = request.execute()
  if (response['pageInfo']['totalResults']) == 0:
  	return ('not subscribed')



################################################ Code to get current user's id
  request = youtube.channels().list(
      part="id",
      mine=True
  )
  response = request.execute()

  userid = (response['items'][0]['id'])
################################################

  record = SUBS.query.filter_by(youtube_id = userid).first()
  if record == None:
  	record = SUBS(userid, email, 0)
  	db.session.add(record)
  	db.session.commit()
  	record = SUBS.query.filter_by(youtube_id = userid).first()
  	print(record)
  

  num_referrals = record.num_referred
  referral_link = "http://localhost:5000/referral/"+str(userid)





  # print(response)
  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  return ("user id is: " + str(userid) + "\nuser email is: " + str(email) + "\nnumber referred so far is: "+str(num_referrals) + "\nreferral link is: "+str(referral_link))


@app.route('/referral/<referrer_id>')
def referral(referrer_id):
  flask.session['source'] = 1
  flask.session['referrer_id'] = referrer_id

  record = SUBS.query.filter_by(youtube_id = referrer_id).first()
  if record == None:
  	print(referrer_id)
  	return('not a real referral id')


  if 'credentials' not in flask.session:
  	# serve html page, which redirects to /authorize
    return flask.redirect('/authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  try:
  	email = (get_user_email(flask.session['credentials']['token'])['email']) #obtain user email
  except:
  	return flask.redirect('/authorize')

  youtube = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)



  ##### TODO: 
  # Get user id, check if in database already
  # if not, check if subbed already
  	# if subbed, add to db, say already subbed thanks
  	# if not, autosub, credit referrer, add to db

  request = youtube.channels().list(
      part="id",
      mine=True
  )
  response = request.execute()
  userid = (response['items'][0]['id'])
  record = SUBS.query.filter_by(youtube_id = userid).first()
  if record != None:
  	return ('already subbed, thanks tho')



  #### checking if user is subscribed
  request = youtube.subscriptions().list(
        part="snippet,contentDetails",
        forChannelId="UC9BNjNQvbSRWzYrF51UzXyQ",
        mine=True
    )
  response = request.execute()
  if (response['pageInfo']['totalResults']) != 0:
  	record = SUBS(userid, email, 0)
  	db.session.add(record)
  	db.session.commit()
  	return('already subbed, thanks tho')


  # this is where we autosub referred accounts
  request = youtube.subscriptions().insert(
    part='snippet',
    body=dict(
      snippet=dict(
        resourceId=dict(
          channelId='UC9BNjNQvbSRWzYrF51UzXyQ'
        )
      )
    ))
  response = request.execute()

  referrer = SUBS.query.filter_by(youtube_id = referrer_id).first()
  referrer.num_referred = referrer.num_referred + 1
  db.session.add(referrer)
  db.session.commit()

  newsub = SUBS(userid, email, 0)
  db.session.add(newsub)
  db.session.commit()

  return('you have been subscribed, and your referrer has been credited. Thank you!')




def get_user_email(access_token):
    r = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            params={'access_token': access_token})
    return r.json()


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 5000, debug=True)











