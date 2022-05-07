# This program is going to interact with the public virustotal api and get requests back
# Virus Total V2 API Docs: https://developers.virustotal.com/v2.0/reference/getting-started
# ---------


# user votes (its the newer api but a good reference)
# https://www.virustotal.com/api/v3/urls/{url_id}/user_votes
# https://developers.virustotal.com/reference/objects

# Source Video
# https://youtu.be/A-mjWOE9Mcc?t=346

# Links used:
# Find and replace in Python: https://www.geeksforgeeks.org/python-string-replace/
# split string python: https://www.w3schools.com/python/ref_string_split.asp

'''
Overview:
Program will ask user to look at a few sites and see if they are malicious
User will enter if they think any of the sites are malicous and, enter a yes or no in a variable
It will then query the results, compare them to what the user wrote and store the outputs
'''


# -=-=-=-=-
# Imports
# -=-=-=-=-
import requests
import time 
import json
import datetime
import os

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
def writeOutToFile(outgoingData,currentDatetime,filenamePrefix,parentDirectoryPath):
    with open(f'./{parentDirectoryPath}/{filenamePrefix}{currentDatetime}.json', 'w') as z:
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



# --- Function to Cut off front
def cut_off_http(siteToUse):
    # Remove front of site
    cutDownName = siteToUse.replace('https://', '')

    return cutDownName


#  --- Function to make folder --- 
# source: https://www.geeksforgeeks.org/create-a-directory-in-python/
def makeFolder(directory):
    
    # Parent Directory path
    parent_dir = "./"
    
    # Path
    path = os.path.join(parent_dir, directory)
    
    # Create the directory
    # 'GeeksForGeeks' in
    # '/home / User / Documents'
    os.mkdir(path)
    print("Directory '% s' created" % directory)
    print(" ")
    
    return directory

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

# Grab current date & time from function & store in variable
use_this_datetime = defang_datetime()



# -=-=-=-=-
#
# MAIN
# 
# -=-=-=-=-

# Variable to store user's name, will not proceed until it is filled
users_name = ''
while users_name == '':
    users_name = input('Howdy! What is your name? ')
print(f'Hi there, {users_name}, it is nice to meet you!\nGet ready to play a game.')

# array of user's answers
user_answers = []

# api_key grabbed here from user (could also look for a file)
api_key = input("Input your API key: ")
print(api_key)


# making path to parent directory
ParentDirectory = f'VirusTotal_APIv2_Scan_{use_this_datetime}'

# make parent directory based on IP
makeFolder(ParentDirectory)


# print out seperator
with open('Scan_Log.txt','a') as vt:
    vt.write('\n\n-=-=-=-=-=-=-=-=-=-=-=-\n') and vt.write(f'Run on {use_this_datetime}') and vt.write('\n-=-=-=-=-=-=-=-=-=-=-=-\n')

# iterating through list of sites
for site in target_addresses:

    # making dictoriary to store all of the data from the site to output to json
    siteInfoArray = []

    # incriment count
    count = count + 1

    # get new name for folder
    outputPrefix = makeOutputFileName(site,count)

    # Cut off https:// form site
    removed_front = cut_off_http(site)


# --- update array with site name and date time
    siteInfoArray.append(f"The name of this site is: {removed_front}")
    siteInfoArray.append(f"The day this test was run was: {datetime.datetime.now()}")

# --- construct report scan url 
    # Indicating that scans are comming next
    siteInfoArray.append(f"----- SCANS -----")

    # constructing url with variables
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    #print(url)


    params1 = {'apikey': api_key, 'resource': site}
    response = requests.get(url, params=params1)
    response_json = json.loads(response.content)

    #print(response.text)

    # Update array with comment data
    siteInfoArray.append(response_json)

    # wait until next response
    time.sleep(15)


# --- construct comments url 
    # Indicating that comments are comming next
    siteInfoArray.append(f"----- COMMENTS -----")

    # constructing url with variables
    url = f"https://www.virustotal.com/vtapi/v2/comments/get?apikey={api_key}&resource={removed_front}"
    #print(url)

    # get comment info from api, send data and key
    headers = {"Accept": "application/json"}
    response = requests.get(url, headers=headers)
    response_json = json.loads(response.content)

    #print(response.text)


    # Update array with comment data
    siteInfoArray.append(response_json)

# ---- 

    # Write out full response in
    writeOutToFile(siteInfoArray,use_this_datetime,outputPrefix,ParentDirectory)
    #writeOutToFile(siteInfoArray,outputPrefix)


    # wait until next response
    time.sleep(15)




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



