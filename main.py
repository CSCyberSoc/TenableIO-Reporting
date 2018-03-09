import requests
import json
from prettyprinter import cpprint, set_default_config
from apiVars import *
import os
import csv
from dict_utils import *

# ------------------------- Authentication Header ---------------------
header = {'X-ApiKeys': 'accessKey=' + apiAccessKey + '; secretKey=' + apiSecretKey}

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

        with open('vulnCSV.csv', 'w') as csvfile:
            fieldname = ['info.counts.vulnerabilities.total', 'info.aws_subnet_id', 'info.aws_ec2_instance_state_name', 'info.aws_availability_zone', 'info.qualys_host_id', 'info.tags', 'info.created_at', 'info.tenable_uuid', 'info.system_type', 'info.time_start', 'info.counts.audits.statuses', 'info.mcafee_epo_guid', 'info.aws_ec2_instance_type', 'info.has_agent', 'info.aws_ec2_instance_id', 'info.mac_address', 'info.ssh_fingerprint', 'info.netbios_name', 'info.counts.vulnerabilities.severities', 'info.sources', 'info.last_seen', 'info.hostname', 'info.updated_at', 'info.last_authenticated_scan_date', 'info.agent_name', 'info.mcafee_epo_agent_guid', 'info.ipv6', 'info.operating_system', 'info.fqdn', 'info.aws_ec2_instance_group_name', 'info.aws_ec2_name', 'info.aws_ec2_product_code', 'info.qualys_asset_id', 'info.time_end', 'info.counts.audits.total', 'info.aws_ec2_instance_ami_id', 'info.azure_instance_instance_id', 'info.aws_region', 'info.uuid', 'info.id', 'info.first_seen', 'info.last_licensed_scan_date', 'info.bios_uuid', 'info.aws_owner_id', 'info.ipv4', 'info.aws_vpc_id', 'severity', 'see_also', 'solution', 'synopsis', 'count', 'description', 'reference_information', 'plugin_details.publication_date', 'vulnerability_information.exploitability_ease', 'risk_information.cvss_temporal_score', 'risk_information.stig_severity', 'risk_information.cvss3_base_score', 'plugin_details.version', 'risk_information.cvss3_temporal_vector', 'vulnerability_information.cpe', 'risk_information.cvss_base_score', 'vulnerability_information.asset_inventory', 'plugin_details.severity', 'vulnerability_information.vulnerability_publication_date', 'risk_information.cvss3_temporal_score', 'plugin_details.family', 'risk_information.risk_factor', 'vulnerability_information.exploit_frameworks', 'plugin_details.name', 'risk_information.cvss3_vector', 'discovery.seen_last', 'vulnerability_information.exploited_by_nessus', 'risk_information.cvss_temporal_vector', 'vulnerability_information.in_the_news', 'plugin_details.type', 'vulnerability_information.default_account', 'vulnerability_information.exploit_available', 'vulnerability_information.malware', 'vulnerability_information.exploited_by_malware', 'plugin_details.modification_date', 'vulnerability_information.unsupported_by_vendor', 'vulnerability_information.patch_publication_date', 'discovery.seen_first', 'risk_information.cvss_vector', 'info.solution', 'info.vulnerability_information.cpe', 'info.risk_information.cvss_temporal_score', 'info.vulnerability_information.malware', 'info.vulnerability_information.asset_inventory', 'info.risk_information.cvss3_vector', 'info.vulnerability_information.in_the_news', 'info.risk_information.cvss3_base_score', 'info.description', 'info.vulnerability_information.default_account', 'info.risk_information.risk_factor', 'info.discovery.seen_last', 'info.synopsis', 'info.vulnerability_information.exploitability_ease', 'info.vulnerability_information.unsupported_by_vendor', 'info.risk_information.cvss3_temporal_score', 'info.plugin_details.modification_date', 'info.see_also', 'info.vulnerability_information.vulnerability_publication_date', 'info.risk_information.cvss_base_score', 'info.plugin_details.version', 'info.risk_information.cvss_temporal_vector', 'info.plugin_details.family', 'info.plugin_details.publication_date', 'info.plugin_details.type', 'info.discovery.seen_first', 'info.vulnerability_information.exploited_by_malware', 'info.risk_information.stig_severity', 'info.vulnerability_information.exploited_by_nessus', 'info.reference_information', 'info.plugin_details.name', 'info.risk_information.cvss3_temporal_vector', 'info.vulnerability_information.patch_publication_date', 'info.vulnerability_information.exploit_frameworks', 'info.plugin_details.severity', 'info.vulnerability_information.exploit_available', 'info.count', 'info.risk_information.cvss_vector', 'info.severity']
            writer = csv.DictWriter(csvfile, delimiter=',', lineterminator='\n', fieldnames=fieldname)
            writer.writeheader()

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

                    # This is where we're going to grab the asset info
                    # This gets more information about the asset scanned
                    assetInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + key + '/info', headers=headerInfo)
                    assetInfoJson = assetInfo.json()
                    assetInfoDict = dictify(assetInfoJson)
                    assetInfoFlat = flatten_dict(assetInfoDict)

                    for value in idDict[key]['vulnerabilities']:
                        # Making a copy of the original data to merge
                        originalData = idDict[key].copy()
                        assetAndVulnInfoDict = {}

                        # This gets vuln info specific to the asset and plugin ID; key = asset ID
                        assetPluginInfo = requests.get('https://cloud.tenable.com/workbenches/assets/' + key + '/vulnerabilities/' + str(value['plugin_id']) + '/info', headers=headerInfo)
                        assetPluginInfoJson = assetPluginInfo.json()
                        assetPluginInfoDict = dictify(assetPluginInfoJson)

                        for plugin_id in assetPluginInfo:
                            i = 0
                            # This gets more information about that specific vulnerability IE: Exploitable?
                            # This needs to be in a loop for each plugin id
                            vulnPluginInfo = requests.get('https://cloud.tenable.com/workbenches/vulnerabilities/' + str(value['plugin_id']) + '/info', headers=headerInfo)
                            vulnPluginInfoJson = vulnPluginInfo.json()
                            # vulnPluginInfoDict = dict(vulnPluginInfoJson)['info']
                            vulnPluginInfoDict = dictify(vulnPluginInfoJson['info'])
                            vulnPluginInfoFlat = flatten_dict(vulnPluginInfoDict)

                            # what's happening here is the vuln info is being added to the dictionary and combined which is overwriting the existing value
                            # might need to use an array, or append/update info to the dictionary
                            assetAndVulnInfoDict = {**assetInfoFlat, **assetPluginInfoDict, **vulnPluginInfoFlat}
                            assetAndVulnInfoFlat = flatten_dict(assetAndVulnInfoDict)
                            print("printing assetAndVulnInfoFlat")
                            print(assetAndVulnInfoFlat)
                            new_result = vulnPluginInfo
                            assetAndVulnInfoDict[i] = new_result

                            # Declaring CSV Obj
                            # with open('vulns.csv', newline='') as csvfile:

                            writer.writerow(assetAndVulnInfoFlat)

                            i = i + 1

                        # finalData = {**originalData, **assetAndVulnInfoDict, **assetInfoJson}
                        # idDict[key] = finalData
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
            # print("Printing Protocol: ")
            # print("Printing Port: ")
            # print("Printing Exploit Available: ")
            # print("Printing MAC Address: ")
            # print("Printing DNS Name: ")
            # print("Printing Solution: ")
            # print("Printing CVE (if available): ")
            # print("Printing First Discovered: ")
            # print("Printing Last Observed: ")
            # print("Printing Vuln Publication Date: ")
            # print("Printing Patch Publication Date: ")
            # print("Printing Plugin Publication Date: ")
            # print("Printing Plugin Modification Date: ")

        return

getAssets(header)