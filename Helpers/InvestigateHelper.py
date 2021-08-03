from dotenv import load_dotenv
import json
import requests
import os
from pprint import pprint
import sys

load_dotenv()

class Investigator(object):
    def __init__(self):
        self.api_key = os.getenv('API_KEY')
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

    def getRelatedDomains(self, domain):
        '''
        This API method returns a list of domain names that have been 
        frequently requested around the same time (up to 60 seconds before or after) 
        as the given domain name, but that are not frequently associated
         with other domain names.
        '''
        endpoint = '/links/name/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getSecurityInfo(self, domain):
        '''
        The security information API method contains multiple scores or security features, 
        each of which can be used to determine relevant datapoints to build insight on the 
        reputation or security risk posed by the site. No one security information feature 
        is conclusive, instead these features should be looked at in conjunction with one 
        another as part of your security research.
        '''
        endpoint = '/security/name/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getRiskScore(self, domain):
        '''
        The Umbrella Investigate Risk Score is based on an analysis of the lexical 
        characteristics of the domain name and patterns in queries and requests to 
        the domain. It is scaled from 0 to 100, with 100 being the highest risk and 
        0 being no risk at all. Periodically Umbrella updates this score based on 
        additional inputs. A domain blocked by Umbrella receives a score of 100.
        '''
        endpoint = '/domains/risk-score/'
        r = requests.get(self.base_url + endpoint + str(domain), headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getAsInfoByIp(self, ip):
        '''
        This endpoint provides data about ASN & IP relationships, showing 
        how IP addresses are related to each other and to the regional registries. 
        You can also find out more about the IP space associated with an AS with 
        this endpoint and correlate BGP routing information between AS. ASN for 
        an IP Address It can be helpful when querying IP to find which AS 
        (Autonomous System) an IP address is associated with. The AS is part of 
        the BGP routing for that IP. To return the AS information for an IP, use 
        the endpoint /bgp_routes/ip/. A valid result will return an array of hash 
        references. The hash reference will contain information about the AS such 
        as the ASN, the CIDR prefix of the AS, the Internet Registry (RIR) number 
        (0 through 6), the Description of the AS and the creation date for the AS. 
        An empty response will return an empty array reference: [ ]. The IR number 
        corresponds to one of the five Regional Internet Registries (RIR).
        '''
        endpoint = '/bgp_routes/ip/'
        r = requests.get(self.base_url + endpoint + str(ip) + '/as_for_ip.json', headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getAsInfoByAsn(self, asn):
        '''
        A found response to a valid ASN will return an array of hash references. 
        Each hash reference contains two keys: geo and cidr. Geo is a hash reference 
        with the country name and country code (the code corresponds to the country 
        code list for ISO-3166-1 alpha-2). For more information, see ISO 3166-1. CIDR 
        contains the IP prefix for this ASN.
        '''
        endpoint = '/bgp_routes/asn/'
        r = requests.get(self.base_url + endpoint + str(asn) + '/prefixes_for_asn.json', headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getCats(self):
        endpoint = '/domains/categories'
        r = requests.get(self.base_url + '/domains/categories', headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text

    def getReverseCats(self):
        reverse_cat_dict = {}
        cats = self.getCats()
        for c in cats:
            reverse_cat_dict.update({cats.get(c) : c})

        return reverse_cat_dict

    def getSamples(self, domain):
        endpoint = '/samples/'
        r = requests.get(self.base_url + endpoint + domain + '?limit=100&sortby=score', headers=self.header)
        if r.status_code == 200:
            r_json = r.json()
            return r_json
        
        else:
            return r.text