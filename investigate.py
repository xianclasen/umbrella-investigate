from dotenv import load_dotenv
import json
import requests
import os

load_dotenv()

class Investigator():
    def __init__(self):
        self.api_key = API_KEY = os.getenv('API_KEY')
        self.base_url = 'https://investigate.api.umbrella.com'
        self.header = {'Authorization': 'Bearer ' + self.api_key}

    def getCategory(self, domains):
        '''
        Returns the domain status, which is the quickest and easiest 
        way to know whether a domain has been flagged as malicious by 
        the Cisco Security Labs team (score of -1 for status). 
        If the domain is believed to be safe (score of 1), or if it has 
        yet to be given a status (score of 0). This method also returns 
        the security categories and content categories of a domain.
        '''
        endpoint = '/domains/categorization/'
        if isinstance(domains, str) or len(domains) == 1:
            r = requests.get(self.base_url + endpoint + str(domains), headers=self.header)
            r_json = r.json()
        
        elif isinstance(domains, list):
            data = json.dumps(domains)
            r = requests.post(self.base_url + endpoint, headers=self.header, data=data)
            if r.status_code == 200:
                r_json = r.json()
            
            else:
                return str(r.text)

        return r_json
    
    def getVolume(self, domain):
        '''
        This endpoint returns query volume for a domain for the last 30 days. 
        If there is no information about the domain, the server returns an empty array. 
        The most recent 1-2 hours may be blank, as the query takes time to generate.
        '''
        endpoint = '/domains/volume/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text
