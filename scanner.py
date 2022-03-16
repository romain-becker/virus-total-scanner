import os
import hashlib
import requests
import json

from decouple import config

from dotenv import dotenv_values
config = dotenv_values(".env")

location = config['PATH']
files_in_dir = []

# r:root, d:directories, f:files
for r, d, f in os.walk(location):
   for item in f:
      files_in_dir.append(os.path.join(r, item))
         

   
for item in files_in_dir:
    with open(item,"rb") as f:
          bytes = f.read() # read entire file as bytes
          readable_hash = hashlib.sha256(bytes).hexdigest();
          print(readable_hash)


apikey = config['APIKEY']

url = "https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/votes?limit=10"
headers = {"Accept": "application/json",
           "x-apikey": apikey
}


response = requests.request("GET", url, headers=headers)

votes = json.loads(response.text)
print(votes)
print(votes["meta"])
print(votes["meta"]["count"])


