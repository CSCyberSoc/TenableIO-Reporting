import requests
import json
from prettyprinter import cpprint, set_default_config
from apiVars import *
import os
import csv

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
        idArray.append('9267e7e4-6020-4882-9294-b325b7419ee3')

        # Instantiating new dict
        idDict = {}
        for id in idArray:
            idDict[id] = 0

        # Take each ID in the array and plug it into /workbenches/assets/{asset_id}/vulnerabilities to get the plugin ID for each asset
        for id in idArray:
            vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + id + '/vulnerabilities', headers=headerInfo)
            vulnInfoJson = vulnInfo.json()
            # Appends the vulnInfoJson using the id as the parent key
            idDict.update({id:vulnInfoJson})
            vulnInfoDict = {}
            vulnInfoList = []

        # Create dict for results set
        pluginIdVal = {}
        pluginResults = {}

        # For loop to iterate through asset IDs and create key with list as value
        # then add plugin_id's to list in child loop
        for key in idDict.keys():
            # pluginIdVal[key] = list()
            for value in idDict[key]['vulnerabilities']:
                vulnInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + key + '/vulnerabilities/' + str(value['plugin_id']) + '/info', headers=headerInfo)
                # adding the asset ID as the parent key, also adding plugin ID and vuln information
                vulnInfoDict[key] = value['plugin_id'], vulnInfo.content
                print(vulnInfoDict)
                # vulnInfoList.append(vulnInfo)
                # pluginIdVal[key].append(value['plugin_id'])

        # Now we need to lookup asset information and append to dict

        # Scaffolding method to write data to CSV
        #     with open('VulnReport.csv', 'w', newline='') as outfile:
        #         fieldnames = ['Asset Name', 'Application ID', 'Vuln Count']
        #         writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        #         writer.writeheader()
        #         data = [dict(zip(fieldnames, [k, v])) for k, v in newDict.items()]
        #         writer.writerows(data)

        return

getAssets(header)