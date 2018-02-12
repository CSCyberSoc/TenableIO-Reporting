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
        # Commented out while using static id idArray values on like 33 and 34
        # for item in assetParsed:
        #     assetID = item['id']
        #     idArray.append(assetID)
        # cpprint(idArray)

        # Adding static ID values as a control, in lieu of lines 27-30
        idArray.append('756591ee-1281-4094-8b86-1621df975951')
        idArray.append('353df3b6-2c3a-432b-b1bb-97eb41662aa1')

        # Instantiating new dict
        newDict = {}
        for id in idArray:
            newDict[id] = 0

        # Take each ID in the array and plug it into /workbenches/assets/{asset_id}/vulnerabilities to get the plugin ID for each asset
        for id in idArray:
            vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + id + '/vulnerabilities', headers=headerInfo)
            vulnInfoJson = vulnInfo.json()
            # Appends the vulnInfoJson using the id as the parent element
            newDict.update({id:vulnInfoJson})

        # Iterate through the dictionary
        for key, value in newDict.items():
            print(key, value)

         #   i=0
         #   vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/'+idArray[i]+'/vulnerabilities', headers=headerInfo)
         #   vulnInfoJson = vulnInfo.json()
         #   # idArray[i].append(vulnInfoJson)
         #   idArray[i] = idArray[i]+str(vulnInfoJson)
         #   cpprint(idArray[i])
         #   print(' \n')
         #   print(' this is the current value of i \n' + str(i))
         #   i=i+1

        #print("Current value of idArray \n")
        #print(idArray)

        return
getAssets(header)