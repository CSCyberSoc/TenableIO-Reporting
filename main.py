import requests
import json
from prettyprinter import cpprint, set_default_config
from apiVars import *

# ------------------------- Authentication --------------------------------
# API Call to generate and store session token
payload = {'username': apiUsername, 'password': apiPass}
sessionToken = requests.post('https://cloud.tenable.com/session', data=json.dumps(payload))
tokenResponse = sessionToken.json()

# Final parsed token for use
tokenParsed = tokenResponse['token']
print(tokenParsed)

# Construct the headers needed for api calls
header = {'X-Cookie': 'token='+tokenParsed}

# ------------------------------ Get Scan ---------------------------
scanID = input("Enter scan ID \n") # Ex: 601 is SOC Agent Scan
getScanInfo = requests.get('https://cloud.tenable.com/scans/'+scanID, headers=header)
scannerResponse = getScanInfo.json()
cpprint(scannerResponse)