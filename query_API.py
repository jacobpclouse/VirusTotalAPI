# This program is going to interact with the public virustotal api and get requests back
'''
To ensure security, I will ask the user to input their API key from the bash terminal (or from a seperat file that is not tracked)
 -- Could also pass key as command line arguments after the python command


        https://developers.virustotal.com/reference/objects
Example api format: https://www.virustotal.com/api/v3/{collection name}/{object id}

'''




# -=-=-=-=-
# Imports
# -=-=-=-=-
import requests
import time 
import json

# -=-=-=-=-
# Functions
# -=-=-=-=-



# -=-=-=-=-
# Variables
# -=-=-=-=-

target_addresses = [
    'https://www.speedtest.net/',
    'https://docs.perfsonar.net/esmond_api_python.html',
    'https://www.geeksforgeeks.org/',
    'https://www.google.com/'
]


# -=-=-=-=-
#
# MAIN
# 
# -=-=-=-=-

# Get API Key var from user
userApiKey = input("Input your API key: ")
print(userApiKey)


# user votes
# https://www.virustotal.com/api/v3/urls/{url_id}/user_votes

#https://youtu.be/A-mjWOE9Mcc?t=346