# This program is going to interact with the public virustotal api and get requests back
# ---------


# user votes
# https://www.virustotal.com/api/v3/urls/{url_id}/user_votes

# Source Video
#https://youtu.be/A-mjWOE9Mcc?t=346

# Links used:
# Find and replace in Python: https://www.geeksforgeeks.org/python-string-replace/
# split string python: https://www.w3schools.com/python/ref_string_split.asp

'''
To ensure security, I will ask the user to input their API key from the bash terminal (or from a seperat file that is not tracked)
 -- Could also pass key as command line arguments after the python command


        https://developers.virustotal.com/reference/objects
Example api format: https://www.virustotal.com/api/v3/{collection name}/{object id}

'''

###IDEAS:
# perhaps use the graphing python function to show a heatmap of how many sites flagged it?
# load data coming back into text file and dicitonary


# -=-=-=-=-
# Imports
# -=-=-=-=-
import requests
import time 
import json

# -=-=-=-=-
# Functions
# -=-=-=-=-

#  --- Function to write out to file --- 
def writeOutToFile(outgoingData,filenamePrefix):
    with open(f'{filenamePrefix}.json', 'a') as z:
        json.dump(outgoingData,z,indent=2)


def makeOutputFileName(incomingURL,currentCount):
    # remove prefix https, replace with count
    newName = incomingURL.replace('https://www.', f'{currentCount}_')

    # split on .
    newName = newName.split('.')
    print(newName[0])

    return newName[0]

# -=-=-=-=-
# Variables
# -=-=-=-=-

# addresses to test
target_addresses = [
    'https://www.speedtest.net/',
    'https://www.geeksforgeeks.org/',
    'https://www.google.com/',
    'https://www.threatcrowd.org/',
    'https://www.bing.com'
]

# current count
count = 0

# -=-=-=-=-
#
# MAIN
# 
# -=-=-=-=-

# api_key grabbed here from user (could also look for a file)
api_key = input("Input your API key: ")
print(api_key)

# api Url to send to (will adapt for v3)
url = 'https://www.virustotal.com/vtapi/v2/url/report'


# iterating through list of sites
for site in target_addresses:

    # incriment count
    count = count + 1

    # get new name for folder
    outputPrefix = makeOutputFileName(site,count)

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


    # Write out full response in
    writeOutToFile(response_json,outputPrefix)

    # wait until next response
    time.sleep(15)

    
# print out seperator
print ("-=-=-=-=-=-=-=-=-")
# with open('vt_results.txt','a') as vt:


