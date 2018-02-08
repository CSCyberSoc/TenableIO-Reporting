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

# ------------------------------ Get Assets ---------------------------
# Gets the list of the assets so that we can pull the pulgin id in the next query
def getAssets(headerInfo):
        getAssetList = requests.get('https://cloud.tenable.com/assets/', headers=headerInfo)
        assetList = getAssetList.json()
        assetParsed = assetList['assets']
        idArray = []
        for item in assetParsed:
            assetID = item['id']
            idArray.append(assetID)
        print(idArray)

        # take each ID in the array and plug it into /workbenches/assets/{asset_id}/vulnerabilities
        vulnArray = []
        for id in idArray:
            vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/'+id+'vulnerabilities', headers=headerInfo)
            vulnArray.append(vulnInfo)
            print(vulnInfo)
            # Receiving error 405 - method is not allowed
            # start writing to CSV from here?
        print(vulnArray)
        return

getAssets(header)

# ------------------------------ Get PluginID ---------------------------
# def getPluginID(headerInfo):
#     assetReturn = getAssets(header)
#     cpprint(assetReturn)


    # API call for plugin ID

#     return
#
# getPluginID(header)