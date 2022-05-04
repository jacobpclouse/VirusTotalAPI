# source video: https://www.youtube.com/watch?v=A-mjWOE9Mcc


from collections import _VT_co
from urllib import response
import requests
import time
import json


indicators = [
    'https://www.threatcrowd.org/',
    'https://www.jacobpclouse.com/'
]


api_key = 'api_key_here'


url = 'https://www.virustotal.com/vtapi/v2/url/report'



for site in indicators:
    params1 = {'apikey': api_key, 'resource': site}
    response = requests.get(url, params=params1)
    response_json = json.loads(response.content)

    if response_json['positives'] <= 0:
        with open('vt_results.txt','a') as vt:
            vt.write(site) and vt.write('-\tNot Malicious\n')
    
    
    elif 1 >= response_json['positives'] >= 3:
        with open('vt_results.txt','a') as vt:
            vt.write(site) and vt.write('-\tPossibly Malicious\n')
    
    
    elif response_json['positives'] >= 4:
        with open('vt_results.txt','a') as vt:
            vt.write(site) and vt.write('-\tMalicious!\n')

    else:
        print('url not found')

    time.sleep(15)