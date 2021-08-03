import base64
from dotenv import load_dotenv
import json
import requests
import os

load_dotenv()

def base64EncodeCreds(key, secret):
    unencoded = key + ':' + secret
    encoded_bytes = base64.b64encode(unencoded.encode('utf-8'))
    encoded_string = str(encoded_bytes, 'utf-8')

    return encoded_string

def getToken(org, creds):
    auth_uri = 'https://management.api.umbrella.com/auth/v2/oauth2/token'
    headers = {
        'X-Umbrella-OrgID': org,
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + creds
        }
    r = requests.post(auth_uri, headers=headers)
    r_json = r.json()

    return r_json

class Reporter(object):
    def __init__(self):
        self.org = os.getenv('ORG')
        self.key = os.getenv('REPORTING_KEY')
        self.secret = os.getenv('REPORTING_TOKEN')
        self.creds = base64EncodeCreds(self.key, self.secret)
        self.base_url = 'https://reports.api.umbrella.com/v2'
        self.token_json = getToken(self.org, self.creds)
        self.token = self.token_json['access_token']
        self.header = {'Authorization': 'Bearer ' + self.token}

    def getActivityLastHour(self):
        endpoint = '/organizations/' + self.org + '/activity/'
        parameters = '?from=-1hours&to=now'
        params = {
            'from': '-1hours',
            'to': 'now'
            }
        r = requests.get(self.base_url + endpoint, params=params, headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        elif r.status_code == 403:
            self.token = getToken(self.org, self.creds)['access_token']
            r = requests.get(self.base_url + endpoint, params=params, headers=self.header)

            if r.status_code == 200:
                r_json = r.json()
                return r_json

            else:
                return r.text
            
        else:
            return r.text