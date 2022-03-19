#from asyncore import read
import os
import hashlib
import requests
import json
import sys
from colors import *


from decouple import config

from dotenv import dotenv_values
config = dotenv_values(".env")

location = config['PATH']
files_in_dir = []


# r:root, d:directories, f:files
for r, d, f in os.walk(location):
   for item in f:
      files_in_dir.append(os.path.join(r, item))
   
List = []

for item in files_in_dir:
    with open(item,"rb") as f:
          bytes = f.read() # read entire file as bytes
          readable_hash = hashlib.sha256(bytes).hexdigest();
          List.append(str(readable_hash)) 
          #print(List)
          
apikey = config['APIKEY']


for readable_hash in List:
    url = "https://www.virustotal.com/api/v3/files/" + str(readable_hash)  
    header = {"Accept": "application/json",
              "x-apikey": apikey
             }
    response = requests.get(url, headers=header)
    for item in files_in_dir:
      print(item)
    report = json.loads(response.text)
    try:  
      report['data']
      sys.stdout.write(BOLD)
      print("\n[Last_analysis_stats] ")
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
      print("[Total_votes] ")
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
      print('FILE NOT FOUND')

  



