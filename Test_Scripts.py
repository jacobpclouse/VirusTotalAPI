import requests
import json

url = 'https://www.virustotal.com/vtapi/v2/url/report'

params = {'apikey': '09162bd8f5eacd612409282206b421e15060e4ae6af3098987b085c76056a7ce', 'resource': 'https://www.threatcrowd.org/'}

response = requests.get(url, params=params)
response_json = json.loads(response.content)

print(response_json)