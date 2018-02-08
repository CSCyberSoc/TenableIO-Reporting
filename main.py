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
        # for item in assetParsed:
        #     assetID = item['id']
        #     idArray.append(assetID)
        # cpprint(idArray)

        # this is just to target 2 IDs as a control
        idArray.append('756591ee-1281-4094-8b86-1621df975951')
        idArray.append('353df3b6-2c3a-432b-b1bb-97eb41662aa1')
        print("Current values in idArray \n")
        print(idArray)

        # take each ID in the array and plug it into /workbenches/assets/{asset_id}/vulnerabilities to get the plugin ID for each asset
        for id in idArray:
            i=0
            vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/'+idArray[i]+'/vulnerabilities', headers=headerInfo)
            vulnInfoJson = vulnInfo.json()
            # idArray[i].append(vulnInfoJson)
            idArray[i] = idArray[i]+str(vulnInfoJson)
            cpprint(idArray[i])
            print(' \n')
            print(' this is the current value of i \n' + str(i))
            i=i+1

        print("Current value of idArray \n")
        print(idArray)

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