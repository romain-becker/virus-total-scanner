from logging import exception
from multiprocessing.connection import wait
import os
import hashlib
from time import sleep
from urllib import response
import requests
import json
import sys
from colors import *
from decouple import config
from dotenv import dotenv_values

config = dotenv_values(".env")

apikey = config['APIKEY']
location = config['PATH']
files_in_dir = []
List = []

sys.stdout.write(BOLD)
print("[FILES TO SCAN]")
sys.stdout.write(RESET)

# r:root, d:directories, f:files
for r, d, f in os.walk(location):
  for item in f:
    print(item)
    files_in_dir.append(os.path.join(r, item))

print("\n")


for item in files_in_dir:
    with open(item,"rb") as f:
          bytes = f.read() # read entire file as bytes
          readable_hash = hashlib.sha256(bytes).hexdigest();
          List.append(str(readable_hash)) 
          

numberOfFiles = len(List)  


for readable_hash in List:
    sys.stdout.write(BOLD)
    print("[SHA-256]")
    sys.stdout.write(RESET)
    print(readable_hash)
    url = "https://www.virustotal.com/api/v3/files/" + str(readable_hash)  
    header = {"Accept": "application/json",
              "x-apikey": apikey
             }
    response = requests.get(url, headers=header)
    # print(response.status_code, response.reason)
    if numberOfFiles >= 4:
        sleep(15)
    for item in files_in_dir:
      report = json.loads(response.text)
    try:  
      report['data']
      sys.stdout.write(BOLD)
      print("\n[LAST ANALYSIS STATS] ")
      sys.stdout.write(RESET)
      print("harmless: ", end="")
      sys.stdout.write(GREEN)
      print(report['data']['attributes']['last_analysis_stats']['harmless'])
      sys.stdout.write(RESET)
      print("type-unsupported: ", end="")
      sys.stdout.write(ORANGE)
      print(report['data']['attributes']['last_analysis_stats']['type-unsupported'])
      sys.stdout.write(RESET)
      print("suspicious: ", end="")
      sys.stdout.write(RED)
      print(report['data']['attributes']['last_analysis_stats']['suspicious'])
      sys.stdout.write(RESET)
      print("confirmed-timeout: ", end="")
      sys.stdout.write(ORANGE)
      print(report['data']['attributes']['last_analysis_stats']['confirmed-timeout'])
      sys.stdout.write(RESET)
      print("timeout: ", end="")
      sys.stdout.write(ORANGE)
      print(report['data']['attributes']['last_analysis_stats']['timeout'])
      sys.stdout.write(RESET)
      print("failure: ", end="")
      sys.stdout.write(ORANGE)
      print(report['data']['attributes']['last_analysis_stats']['failure'])
      sys.stdout.write(RESET)
      print("malicious: ", end="")
      sys.stdout.write(RED)
      print(report['data']['attributes']['last_analysis_stats']['malicious'])
      sys.stdout.write(RESET)
      print("undetected: ", end="")
      sys.stdout.write(GREEN)
      print(report['data']['attributes']['last_analysis_stats']['undetected'])
      sys.stdout.write(RESET)
      print("\n")
      sys.stdout.write(BOLD)
      print("[TOTAL VOTES] ")
      sys.stdout.write(RESET)
      print("harmless: ", end="")
      sys.stdout.write(GREEN)
      print(report['data']['attributes']['total_votes']['harmless'])
      sys.stdout.write(RESET)
      print("malicious: ", end="")
      sys.stdout.write(RED)
      print(report['data']['attributes']['total_votes']['malicious'])
      sys.stdout.write(RESET)
      print("\n")
    except:
      if response.status_code == 404: 
        # print(response.status_code)
        url = "https://www.virustotal.com/api/v3/files/" + str(readable_hash) + "/analyse"
        headers = { 
            "Accept": "application/json",
            "x-apikey": "6173a41d7f5e0973fe7e60783bdc9ee7fc96d63a2d97e6dd104b295730757c13"
          }
        response2 = requests.request("POST", url, headers=headers)
        if response2.status_code == 200:
          print(response2.text)
        if response2.status_code == 404:
          print('ERROR')


 








  
  
     
    
       
        
    


