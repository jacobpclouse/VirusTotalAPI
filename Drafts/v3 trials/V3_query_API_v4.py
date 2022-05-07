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
# *** SCAN URL LINK V3: https://developers.virustotal.com/reference/scan-url

# -=-=-=-=-
# Imports
# -=-=-=-=-
import requests
import time 
import json
import datetime

# -=-=-=-=-
# Functions
# -=-=-=-=-

# --- Function to print out my Logo ---
def myLogo():
    print("Created and Tested by: ")
    print("   __                  _         ___ _                       ")
    print("   \ \  __ _  ___ ___ | |__     / __\ | ___  _   _ ___  ___  ")
    print("    \ \/ _` |/ __/ _ \| '_ \   / /  | |/ _ \| | | / __|/ _ \ ")
    print(" /\_/ / (_| | (_| (_) | |_) | / /___| | (_) | |_| \__ \  __/ ")
    print(" \___/ \__,_|\___\___/|_.__/  \____/|_|\___/ \__,_|___/\___| ")


#  --- Function to write out to file --- 
def writeOutToFile(outgoingData,filenamePrefix):
    with open(f'{filenamePrefix}.json', 'a') as z:
        json.dump(outgoingData,z,indent=2)


# --- Function to create site JSON file name ---
def makeOutputFileName(incomingURL,currentCount):
    # remove prefix https, replace with count
    newName = incomingURL.replace('https://www.', f'{currentCount}_')

    # split on .
    newName = newName.split('.')
    print(newName[0])

    return newName[0]


# --- Function to Defang date time ---
def defang_datetime():
    current_datetime = f"_{datetime.datetime.now()}"

    current_datetime = current_datetime.replace(":","_")
    current_datetime = current_datetime.replace(".","-")
    current_datetime = current_datetime.replace(" ","_")
    
    return current_datetime


# --- Function to Cut off front and make api call
def get_api_results(siteToUse,currentCount):
    # Remove front of site
    cutDownName = siteToUse.replace('https://', '')

    # Site Url
    url = f'https://www.virustotal.com/api/v3/urls/{cutDownName}'
    print(url)

    # get new name for folder
    outputPrefix = makeOutputFileName(siteToUse,currentCount)

    headers = {
    "Accept": "application/json",
    "x-apikey": "09162bd8f5eacd612409282206b421e15060e4ae6af3098987b085c76056a7ce"
    }

    response = requests.get(url, headers=headers)
    print('response')
    response_json = json.loads(response.content)

    #print(response_json['scans'])
    # Write out full response in
    writeOutToFile(response_json,outputPrefix)

    # wait until next response
    time.sleep(15)    



# --- Function to Cut off front and make api call
def get_api_results_id(siteToUse,currentCount,limitNum):
    # Remove front of site
    cutDownName = siteToUse.replace('https://', '')

    # Site Url
    url = f"https://www.virustotal.com/api/v3/urls/{cutDownName}/comments?limit={limitNum}"
    print(url)

    # get new name for folder
    outputPrefix = makeOutputFileName(siteToUse,currentCount)

    headers = {
    "Accept": "application/json",
    "x-apikey": "09162bd8f5eacd612409282206b421e15060e4ae6af3098987b085c76056a7ce"
    }

    response = requests.get(url, headers=headers)
    print('response')
    response_json = json.loads(response.content)

    #print(response_json['scans'])
    # Write out full response in
    writeOutToFile(response_json,outputPrefix)

    # wait until next response
    time.sleep(15)    


    


# -=-=-=-=-
# Variables
# -=-=-=-=-

# api Url to send to (will adapt for v3)
#url = 'https://www.virustotal.com/vtapi/v2/url/report'
#url = f'https://www.virustotal.com/vtapi/v2/{collection_name}/{object_id}'
#https://www.virustotal.com/api/v3/urls/id
url = 'https://www.virustotal.com/api/v3/urls/id'

# addresses to test
target_addresses = [
    'https://www.speedtest.net/',
    'https://www.geeksforgeeks.org/',
    'https://www.google.com/',
    'https://www.threatcrowd.org/',
    'https://www.bing.com'
]

# target address IDs
target_address_ids = [
    f'https%3A%2F%2Fwww.speedtest.net%2F',
    f'https%3A%2F%2Fwww.geeksforgeeks.org%2F',
    f'https%3A%2F%2Fwww.google.com%2F',
    f'https%3A%2F%2Fwww.threatcrowd.org%2F',
    f'https%3A%2F%2Fwww.bing.com'
]

# limit number for number of comments
limit_number = 10

# current count
count = 0

# Grab current date & time from function & store in variable
use_this_datetime = defang_datetime()



# -=-=-=-=-
#
# MAIN
# 
# -=-=-=-=-


# api_key grabbed here from user (could also look for a file)
#api_key = input("Input your API key: ")
#print(api_key)


# print out seperator
with open('vt_results.txt','a') as vt:
    vt.write('\n\n-=-=-=-=-=-=-=-=-=-=-=-\n') and vt.write(f'Run on {use_this_datetime}') and vt.write('\n-=-=-=-=-=-=-=-=-=-=-=-\n')



# iterating through list of sites
#for site in target_addresses:
for site in target_address_ids:

# break out into its own function

    # incriment count
    count = count + 1

    # Function to get report
    #get_api_results(site,count)
    get_api_results_id(site,count,limit_number)



'''
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
'''


    

# end of program signal
print (" ")
myLogo()



