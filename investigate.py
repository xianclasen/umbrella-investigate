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

    def getCooccurances(self, domain):
        '''
        This API method returns a list of co-occurences for the specified domain. 
        A co-occurrence is when two or more domains are accessed by the same users 
        within a small window of time. Co-occurring domains are not necessarily a bad thing; 
        legitimate sites co-occur with each other as a part of normal web activity. 
        However, unusual or suspicious co-occurence can provide additional information 
        regarding attacks. To determine co-occurrences for a domain, a small time window of 
        traffic across all of our datacenters is taken. Then, we look at the sites that end 
        users were visiting before and after the domain requested in the API call.
        '''
        endpoint = '/recommendations/name/'
        r = requests.get(self.base_url + endpoint + str(domain) + '.json', headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getPdnsByName(self, domain):
        '''
        The Passive DNS endpoint provides historical data from our resolvers for 
        domains, IPs, and other resource records.
        '''
        endpoint = '/pdns/name/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getPdnsByDomain(self, domain):
        '''
        Returns the Resource Record (RR) data for DNS responses, 
        and categorization data, where the answer (or rdata) is the domain(s).
        '''
        endpoint = '/pdns/domain/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getPdnsByIp(self, ip):
        '''
        Returns the Resource Record (RR) data for DNS responses, 
        and categorization data, where the answer (or rdata) is the domain(s).
        '''
        endpoint = '/pdns/ip/'
        r = requests.get(self.base_url + endpoint + str(ip), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getRawPdns(self, raw):
        '''
        Returns the Resource Record (RR) data for DNS responses, 
        and categorization data, where the answer (or rdata) could be anything.
        '''
        endpoint = '/pdns/raw/'
        r = requests.get(self.base_url + endpoint + str(raw), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text
