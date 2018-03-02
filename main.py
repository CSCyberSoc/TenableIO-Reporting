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
# Gets the list of the assets so that we can pull the plugin id in the next query
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

        # Loop to iterate through asset grabbing asset information and vulnerability information and adding to idDict
        for key in idDict.keys():
            for value in idDict[key]['vulnerabilities']:
                # Making a copy of the original data to merge
                originalData = idDict[key].copy()
                assetAndVulnInfoDict = {}

                # This gets vuln info specific to the asset and plugin ID; key = asset ID
                assetPluginInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + key + '/vulnerabilities/' + str(value['plugin_id']) + '/info', headers=headerInfo)
                assetPluginInfoJson = assetPluginInfo.json()

                for plugin_id in assetPluginInfoJson:
                    i = 0
                    # This gets more information about that specific vulnerability IE: Exploitable?
                    # This needs to be in a loop for each plugin id
                    vulnPluginInfo = requests.get('https://cloud.tenable.com/workbenches/vulnerabilities/' + str(value['plugin_id']) + '/info', headers=headerInfo)
                    vulnPluginInfoJson = vulnPluginInfo.json()

                    # what's happening here is the vuln info is being added to the dictionary and combined which is overwriting the existing value
                    # might need to use an array, or append/update info to the dictionary
                    # assetAndVulnInfoDict = {**assetPluginInfoJson, **vulnPluginInfoJson}
                    new_result = vulnPluginInfoJson
                    assetAndVulnInfoDict[i] = new_result
                    i = i + 1

                # This gets more information about the asset scanned
                assetInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + key + '/info', headers=headerInfo)
                assetInfoJson = assetInfo.json()
                print("Printing assetAndVulnInfoDict")
                print(assetAndVulnInfoDict)
                finalData = {**originalData, **assetAndVulnInfoDict, **assetInfoJson}
                idDict[key] = finalData
        print(idDict)
        # added idDictJson simply for easier visibility for targeting values
        idDictJson = json.dumps(idDict, indent=4)
        print("Printing idDictJson")
        print(idDictJson)

        print("Printing idDictJson")
        for id in idArray:
            print("Printing idDict at position " + id)
            # print(idDict[id]['vulnerabilities'][0]['count'])
            # print("Printing plugin_id")
            # print(idDict[id]['vulnerabilities'][0]['plugin_id'])
            # print("Printing Plugin Name")
            # print(idDict[id]['vulnerabilities'][0]['plugin_name'])
            # print("Printing Plugin OS (if available): ")
            # print(idDict[id]['info']['operating_system'])
            # print("Printing Severity: ")
            # print(idDict[id]['info']['counts']['vulnerabilities']['severities'][0]['name'])
            # print("Printing IP address: ")
            # print(idDict[id]['info']['ipv4'][0])
            print("Printing Protocol: ")
            print("Printing Port: ")
            print("Printing Exploit Available: ")
            print("Printing MAC Address: ")
            print("Printing DNS Name: ")
            print("Printing Solution: ")
            print("Printing CVE (if available): ")
            print("Printing First Discovered: ")
            print("Printing Last Observed: ")
            print("Printing Vuln Publication Date: ")
            print("Printing Patch Publication Date: ")
            print("Printing Plugin Publication Date: ")
            print("Printing Plugin Modification Date: ")

        return

getAssets(header)