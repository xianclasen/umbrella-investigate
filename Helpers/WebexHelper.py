from dotenv import load_dotenv
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder
import os
import requests

load_dotenv()

class WebexHandler(object):
    def __init__(self):
        self.token = os.getenv('WEBEX_TOKEN')
        self.roomsUri = 'https://webexapis.com/v1/rooms'
        self.messagesUri = 'https://webexapis.com/v1/messages'
        self.headers = {'Authorization': 'Bearer ' + self.token}

    def listRooms(self):
        resp = requests.get(self.roomsUri, headers=self.headers)
        json_resp = json.loads(resp.content)
        return json_resp