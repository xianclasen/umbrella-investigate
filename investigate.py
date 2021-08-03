from dotenv import load_dotenv
import json
import requests
import os
from pprint import pprint
import sys
from Helpers.WebexHelper import WebexHandler
from Helpers.InvestigateHelper import Investigator

if __name__ == '__main__':
    domain = sys.argv[1]
    inv = Investigator()
    cats = inv.getCats()
    category = inv.getCategory(domain)
    sec_cat_num = category[domain]['security_categories']
    content_cat_num = category[domain]['content_categories']

    # CATEGORIES
    print(domain + '\n\n##########\nCategories\n##########\n')
    if sec_cat_num:
        for cat in sec_cat_num:
            print('Security Category: ' + cats[cat])
    if content_cat_num:
        for cat in content_cat_num:
            print('Content Category: ' + cats[cat])

    # RISK SCORE
    print('\n##########\nRisk Score\n##########\n')
    pprint(inv.getRiskScore(domain)['risk_score'])

    # Security Info
    print('\n##########\nSecurity Info\n##########\n')
    print('Attack: ' + str(inv.getSecurityInfo(domain)['attack']))
    print('DGA Score: ' + str(inv.getSecurityInfo(domain)['dga_score']))
    print('Fast Flux: ' + str(inv.getSecurityInfo(domain)['fastflux']))
    print('Threat Type: ' + str(inv.getSecurityInfo(domain)['threat_type']))
    
    # SAMPLES
    samples = inv.getSamples(domain)
    print('\n##########\nSamples\n##########\n')
    #print(len(samples))
    print('Number of samples found: ' + str(samples['totalResults']) + '\n')
    for i in samples['samples']:
        print('Threat Score: ' + str(i['threatScore']))
        print('SHA256: ' + i['sha256'] + '\n')
