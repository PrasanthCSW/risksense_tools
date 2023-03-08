import json
import requests
import json
import time, os, zipfile,pandas as pd,logging,numpy as np
import toml,datetime

dict = toml.load("conf/config.toml")

currentDate = datetime.datetime.now()
currentTime = currentDate.strftime("%H:%M:%S")

connector_name = dict["JIRA"]["connector_name"]
platform = dict["platform"]["platform"]
api_key = dict["platform"]["api_key"]
clientID = dict["platform"]["client_ID"]
user = dict["JIRA"]["user"]
password = dict["JIRA"]["pass"]
instance = dict["JIRA"]["instance"]

#print(platform,clientID,user,password,instance,connector_name)

headers = {
     "content-type": "application/json",
     "x-api-key": api_key     
    }

def get_connectorDetails(JIRAConnectorName):
   response = requests.get("https://{}.risksense.com/api/v1/client/{}/connector?size=250&page=0".format(platform,clientID),headers=headers)
   response_json = json.loads(response.text)
   #print(response_json,JIRAConnectorName)
   connectors = len(response_json["_embedded"]["connectors"])   
   
   for index in range(connectors):
      #print("type",response_json["_embedded"]["connectors"][index]["type"],"name",response_json["_embedded"]["connectors"][index]["name"])
      if (response_json["_embedded"]["connectors"][index]["type"] == "JIRA") and response_json["_embedded"]["connectors"][index]["name"] == JIRAConnectorName:
            connectorID = response_json["_embedded"]["connectors"][index]["id"] 
            break
   return connectorID

def get_userId():
    user_details = requests.get("https://{}.risksense.com/api/v1/user/profile".format(platform),headers=headers)
    user_details = json.loads(user_details.text)
    userID = str(user_details["userId"])
    return userID

def app_level_grouping():
    url = "https://{}.risksense.com/api/v1/client/{}/application/group-by".format(platform,clientID)
    app_name =[]
    payload = json.dumps({
    "metricFields": [
        "Application Count",
        "Application RS3 Critical Risk",
        "Application RS3 High Risk",
        "Application RS3 Medium Risk",
        "Application Asset Criticality 5",
        "Application Asset Criticality 4",
        "Application Asset Criticality 3"
    ],
    "key": "project_name",
    "filters": [
        {
        "field": "scanner_names",
        "exclusive": False,
        "operator": "IN",
        "orWithPrevious": False,
        "implicitFilters": [],
        "value": "BLACKDUCK"
        },
    ],
    "sortOrder": [
        {
        "field": "project_name",
        "direction": "ASC"
        }
    ]
    })

    response = requests.request("POST", url, headers=headers, data=payload)
    #print(response.text,response.status_code)
    jsonified_result = json.loads(response.text)

    for i in range (len(jsonified_result["data"])):
        app_name.append(jsonified_result["data"][i]["project_name"])

    #print(app_name)
    print("\n[+]  Total Applications Grouped by is {}".format(len(app_name)))
    logging.info("\n[+]  Total Applications Grouped by is {}".format(len(app_name)))
    return app_name


def groupby(appname) :
    print("\n[+]  Application '{}' Scanner Plugins are grouped by...".format(appname))
    logging.info("\n[+]  Application '{}' Scanner Plugins are grouped by...".format(appname))
    grp_url = "https://{}.risksense.com/api/v1/client/{}/applicationFinding/group-by".format(platform,clientID)

    payload = json.dumps({
    "metricFields": [
        "App Finding Title",
        "App Finding Scanner Name",
        "App Finding Apps Count",
        "App Finding Open Count",
        "App Finding Closed Count",
        "App Finding VRR Critical Count",
        "App Finding VRR High Count",
        "App Finding VRR Medium Count",
        "App Finding VRR Low Count",
        "App Finding VRR Info Count"
    ],
    "key": "App Finding Scanner Plugin",
    "filters": [
        {
        "field": "webAppAdditionalDetails.project_name",
        "exclusive": False,
        "operator": "IN",
        "orWithPrevious": False,
        "implicitFilters": [],
        "value": appname
        },
        {"field":"riskType","exclusive":False,"operator":"IN","orWithPrevious":False,"implicitFilters":[],"value":"security"}
    ],
    "sortOrder": [
        {
        "field": "App Finding Scanner Plugin",
        "direction": "ASC"
        }
    ]
    })

    response = requests.request("POST", grp_url, headers=headers, data=payload)
    jsonified_result = json.loads(response.text)

    print("\n[+] There are {} scanner plugins for the '{}' application ".format(len(jsonified_result["data"]),appname))
    logging.info("\n[+] There are {} scanner plugins for the '{}' application ".format(len(jsonified_result["data"]),appname))

    return jsonified_result
    
def export(scanner_plugin,name):
    ex_url = "https://{}.risksense.com/api/v1/client/{}/applicationFinding/export".format(platform,clientID)

    payload = json.dumps({
    "fileName": "export",
    "fileType": "CSV",
    "noOfRows": "5000",
    "filterRequest": {
        "filters": [
        {
            "field": "webAppAdditionalDetails.project_name",
            "exclusive": False,
            "operator": "IN",
            "orWithPrevious": False,
            "implicitFilters": [],
            "value": str(name)
        },
        {
            "field": "generic_state",
            "exclusive": False,
            "operator": "EXACT",
            "orWithPrevious": False,
            "implicitFilters": [],
            "value": "Open"
        },
        {
            "field": "found_by_id",
            "exclusive": False,
            "operator": "EXACT",
            "orWithPrevious": False,
            "implicitFilters": [],
            "value": str(scanner_plugin)
        },
        {
        "field":"HAS_CONNECTOR_TICKET",
        "exclusive":False,
        "operator":"EXACT",
        "value": "False"
        },
        {"field":"riskType","exclusive":False,"operator":"IN","orWithPrevious":False,"implicitFilters":[],"value":"security"}
    #    {"field":"generic_state","exclusive":false,"operator":"EXACT","value":"Open"},,{"field":"webAppAdditionalDetails.project_name","exclusive":false,"operator":"IN","value":"Patch Cloud Device Patching"}],"filter":{"field":"found_by_id","exclusive":false,"operator":"IN","value":"","implicitFilters":[]}}
        
        ]
    },
    "exportableFields": [
        {
        "heading": "asset_options",
        "fields": [
            {
            "identifierField": "location",
            "displayText": "Address",
            "sortable": False,
            "fieldOrder": 1,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "addressType",
            "displayText": "Address Type",
            "sortable": False,
            "fieldOrder": 2,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "name",
            "displayText": "Application Name",
            "sortable": False,
            "fieldOrder": 3,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetCriticality",
            "displayText": "Asset Criticality",
            "sortable": False,
            "fieldOrder": 4,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "asset_owner",
            "displayText": "Asset Owner",
            "sortable": False,
            "fieldOrder": 5,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "owner",
            "displayText": "CHECKMARXSAST Scan Owner",
            "sortable": False,
            "fieldOrder": 6,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "critical",
            "displayText": "Critical",
            "sortable": False,
            "fieldOrder": 7,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "exploit",
            "displayText": "Exploit",
            "sortable": False,
            "fieldOrder": 8,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetIdentifiedBy",
            "displayText": "First Asset Identified By",
            "sortable": False,
            "fieldOrder": 9,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetIdentifier",
            "displayText": "First Asset Identifier",
            "sortable": False,
            "fieldOrder": 10,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerFirstDiscoveredOn",
            "displayText": "First Discovered On",
            "sortable": False,
            "fieldOrder": 11,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "platformFirstIngestedOn",
            "displayText": "First Ingested On",
            "sortable": False,
            "fieldOrder": 12,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "groupIds",
            "displayText": "Group Ids",
            "sortable": False,
            "fieldOrder": 13,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "groupNames",
            "displayText": "Group Names",
            "sortable": False,
            "fieldOrder": 14,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "high",
            "displayText": "High",
            "sortable": False,
            "fieldOrder": 15,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "id",
            "displayText": "Id",
            "sortable": False,
            "fieldOrder": 16,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "info",
            "displayText": "Info",
            "sortable": False,
            "fieldOrder": 17,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastAssetIdentifiedBy",
            "displayText": "Last Asset Identified By",
            "sortable": False,
            "fieldOrder": 18,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastAssetIdentifier",
            "displayText": "Last Asset Identifier",
            "sortable": False,
            "fieldOrder": 19,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerLastDiscoveredOn",
            "displayText": "Last Discovered On",
            "sortable": False,
            "fieldOrder": 20,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastFoundOn",
            "displayText": "Last Found On",
            "sortable": False,
            "fieldOrder": 21,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "platformLastIngestedOn",
            "displayText": "Last Ingested On",
            "sortable": False,
            "fieldOrder": 22,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "locationCount",
            "displayText": "Location Count",
            "sortable": False,
            "fieldOrder": 23,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "low",
            "displayText": "Low",
            "sortable": False,
            "fieldOrder": 24,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "medium",
            "displayText": "Medium",
            "sortable": False,
            "fieldOrder": 25,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "metricsOverrideDate",
            "displayText": "Metric Exclude Override Date",
            "sortable": False,
            "fieldOrder": 26,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "metricsOverrideType",
            "displayText": "Metric Exclude Override Status",
            "sortable": False,
            "fieldOrder": 27,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "metricsOverrideUser",
            "displayText": "Metric Exclude Override User",
            "sortable": False,
            "fieldOrder": 28,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "network",
            "displayText": "Network",
            "sortable": False,
            "fieldOrder": 29,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "networkType",
            "displayText": "Network Type",
            "sortable": False,
            "fieldOrder": 30,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "app_name",
            "displayText": "Nexus Lifecycle Application Name",
            "sortable": False,
            "fieldOrder": 31,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "org_name",
            "displayText": "Nexus Lifecycle Organization",
            "sortable": False,
            "fieldOrder": 32,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "stage_name",
            "displayText": "Nexus Lifecycle Stage",
            "sortable": False,
            "fieldOrder": 33,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "osName",
            "displayText": "OS Name",
            "sortable": False,
            "fieldOrder": 34,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "pii",
            "displayText": "PII",
            "sortable": False,
            "fieldOrder": 35,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "account_id",
            "displayText": "Prisma Cloud Compute Account ID",
            "sortable": False,
            "fieldOrder": 36,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "collections",
            "displayText": "Prisma Cloud Compute Collections",
            "sortable": False,
            "fieldOrder": 37,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cluster",
            "displayText": "Prisma Cloud Compute Container Cluster",
            "sortable": False,
            "fieldOrder": 38,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "container_labels_wildcard",
            "displayText": "Prisma Cloud Compute Container Labels",
            "sortable": False,
            "fieldOrder": 39,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "namespace",
            "displayText": "Prisma Cloud Compute Container Namespace",
            "sortable": False,
            "fieldOrder": 40,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "clusters",
            "displayText": "Prisma Cloud Compute Image Clusters",
            "sortable": False,
            "fieldOrder": 41,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "labels_wildcard",
            "displayText": "Prisma Cloud Compute Image Labels",
            "sortable": False,
            "fieldOrder": 42,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "namespaces",
            "displayText": "Prisma Cloud Compute Image Namespaces",
            "sortable": False,
            "fieldOrder": 43,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "rs3",
            "displayText": "RS3",
            "sortable": False,
            "fieldOrder": 44,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "sla_rule_name",
            "displayText": "SLA Name",
            "sortable": False,
            "fieldOrder": 45,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "AssetTagIds",
            "displayText": "Tag Ids",
            "sortable": False,
            "fieldOrder": 46,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "tags",
            "displayText": "Tags",
            "sortable": False,
            "fieldOrder": 47,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsId",
            "displayText": "Tickets Id",
            "sortable": False,
            "fieldOrder": 48,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsLink",
            "displayText": "Tickets Link",
            "sortable": False,
            "fieldOrder": 49,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsStatus",
            "displayText": "Tickets Status",
            "sortable": False,
            "fieldOrder": 50,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrCritical",
            "displayText": "VRR Critical",
            "sortable": False,
            "fieldOrder": 51,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrHigh",
            "displayText": "VRR High",
            "sortable": False,
            "fieldOrder": 52,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrInfo",
            "displayText": "VRR Info",
            "sortable": False,
            "fieldOrder": 53,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrLow",
            "displayText": "VRR Low",
            "sortable": False,
            "fieldOrder": 54,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrMedium",
            "displayText": "VRR Medium",
            "sortable": False,
            "fieldOrder": 55,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            }
        ]
        },
        {
        "heading": "finding_options",
        "fields": [
            {
            "identifierField": "addressType",
            "displayText": "Address Type",
            "sortable": False,
            "fieldOrder": 1,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "appId",
            "displayText": "App Id",
            "sortable": False,
            "fieldOrder": 2,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "name",
            "displayText": "App Name",
            "sortable": False,
            "fieldOrder": 3,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "applicationAddress",
            "displayText": "Application Address",
            "sortable": False,
            "fieldOrder": 4,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetCriticality",
            "displayText": "Asset Criticality",
            "sortable": False,
            "fieldOrder": 5,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "asset_owner",
            "displayText": "Asset Owner",
            "sortable": False,
            "fieldOrder": 6,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assignedTo",
            "displayText": "Assigned To",
            "sortable": False,
            "fieldOrder": 7,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "burpsuite_deeplink",
            "displayText": "BurpSuite Enterprise Deep Link",
            "sortable": False,
            "fieldOrder": 8,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cvss2Score",
            "displayText": "CVSS 2.0",
            "sortable": False,
            "fieldOrder": 9,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cvss2Vector",
            "displayText": "CVSS 2.0 Vector",
            "sortable": False,
            "fieldOrder": 10,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cvss3Score",
            "displayText": "CVSS 3.0",
            "sortable": False,
            "fieldOrder": 11,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cvss3Vector",
            "displayText": "CVSS 3.0 Vector",
            "sortable": False,
            "fieldOrder": 12,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cweIds",
            "displayText": "CWE ID",
            "sortable": False,
            "fieldOrder": 13,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "description",
            "displayText": "Description",
            "sortable": False,
            "fieldOrder": 14,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "dueDate",
            "displayText": "Due Date",
            "sortable": False,
            "fieldOrder": 15,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "due_date_updated_date",
            "displayText": "Due Date Updated On",
            "sortable": False,
            "fieldOrder": 16,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "expireDate",
            "displayText": "Expire Date",
            "sortable": False,
            "fieldOrder": 17,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "exploits",
            "displayText": "Exploits",
            "sortable": False,
            "fieldOrder": 18,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetIdentifiedBy",
            "displayText": "First Asset Identified By",
            "sortable": False,
            "fieldOrder": 19,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "assetIdentifier",
            "displayText": "First Asset Identifier",
            "sortable": False,
            "fieldOrder": 20,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "firstAssignedOn",
            "displayText": "First Assigned On Date",
            "sortable": False,
            "fieldOrder": 21,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerFirstDiscoveredOn",
            "displayText": "First Discovered On",
            "sortable": False,
            "fieldOrder": 22,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "platformFirstIngestedOn",
            "displayText": "First Ingested On",
            "sortable": False,
            "fieldOrder": 23,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vulnerability_id",
            "displayText": "FortifyonDemand Vuln Id",
            "sortable": False,
            "fieldOrder": 24,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "groupIds",
            "displayText": "Group Ids",
            "sortable": False,
            "fieldOrder": 25,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "groupNames",
            "displayText": "Group Names",
            "sortable": False,
            "fieldOrder": 26,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "id",
            "displayText": "Id",
            "sortable": False,
            "fieldOrder": 27,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastAssetIdentifiedBy",
            "displayText": "Last Asset Identified By",
            "sortable": False,
            "fieldOrder": 28,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastAssetIdentifier",
            "displayText": "Last Asset Identifier",
            "sortable": False,
            "fieldOrder": 29,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerLastDiscoveredOn",
            "displayText": "Last Discovered On",
            "sortable": False,
            "fieldOrder": 30,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "lastFoundOn",
            "displayText": "Last Found On",
            "sortable": False,
            "fieldOrder": 31,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "platformLastIngestedOn",
            "displayText": "Last Ingested On",
            "sortable": False,
            "fieldOrder": 32,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "location",
            "displayText": "Location",
            "sortable": False,
            "fieldOrder": 33,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "network",
            "displayText": "Network",
            "sortable": False,
            "fieldOrder": 34,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "networkType",
            "displayText": "Network Type",
            "sortable": False,
            "fieldOrder": 35,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "app_name",
            "displayText": "Nexus Lifecycle Application Name",
            "sortable": False,
            "fieldOrder": 36,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "sonatype_cvss_v2_score",
            "displayText": "Nexus Lifecycle CVSS V2 Score",
            "sortable": False,
            "fieldOrder": 37,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "sonatype_cvss_v3_score",
            "displayText": "Nexus Lifecycle CVSS V3 Score",
            "sortable": False,
            "fieldOrder": 38,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "finding_deeplink",
            "displayText": "Nexus Lifecycle Deep Link",
            "sortable": False,
            "fieldOrder": 39,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "effective_licenses",
            "displayText": "Nexus Lifecycle Effective Licenses",
            "sortable": False,
            "fieldOrder": 40,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "org_name",
            "displayText": "Nexus Lifecycle Organization",
            "sortable": False,
            "fieldOrder": 41,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "policy_name",
            "displayText": "Nexus Lifecycle Policy Name",
            "sortable": False,
            "fieldOrder": 42,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "policy_violation_id",
            "displayText": "Nexus Lifecycle Policy Violation Id",
            "sortable": False,
            "fieldOrder": 43,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "sonatype_score",
            "displayText": "Nexus Lifecycle Score",
            "sortable": False,
            "fieldOrder": 44,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "stage_name",
            "displayText": "Nexus Lifecycle Stage",
            "sortable": False,
            "fieldOrder": 45,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "notes",
            "displayText": "Notes",
            "sortable": False,
            "fieldOrder": 46,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "originalAggregatedSeverity",
            "displayText": "Original Aggregated Severity",
            "sortable": False,
            "fieldOrder": 47,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "osName",
            "displayText": "OS Name",
            "sortable": False,
            "fieldOrder": 48,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "owasp",
            "displayText": "OWASP",
            "sortable": False,
            "fieldOrder": 49,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "parameter",
            "displayText": "Parameter",
            "sortable": False,
            "fieldOrder": 50,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "patchId",
            "displayText": "Patch Id",
            "sortable": False,
            "fieldOrder": 51,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "payload",
            "displayText": "Payload",
            "sortable": False,
            "fieldOrder": 52,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "possiblePatches",
            "displayText": "Possible Patches",
            "sortable": False,
            "fieldOrder": 53,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "solution",
            "displayText": "Possible Solution",
            "sortable": False,
            "fieldOrder": 54,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "account_id",
            "displayText": "Prisma Cloud Compute Account ID",
            "sortable": False,
            "fieldOrder": 55,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "collections",
            "displayText": "Prisma Cloud Compute Collections",
            "sortable": False,
            "fieldOrder": 56,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "cluster",
            "displayText": "Prisma Cloud Compute Container Cluster",
            "sortable": False,
            "fieldOrder": 57,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "container_labels_wildcard",
            "displayText": "Prisma Cloud Compute Container Labels",
            "sortable": False,
            "fieldOrder": 58,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "namespace",
            "displayText": "Prisma Cloud Compute Container Namespace",
            "sortable": False,
            "fieldOrder": 59,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "clusters",
            "displayText": "Prisma Cloud Compute Image Clusters",
            "sortable": False,
            "fieldOrder": 60,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "labels_wildcard",
            "displayText": "Prisma Cloud Compute Image Labels",
            "sortable": False,
            "fieldOrder": 61,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "namespaces",
            "displayText": "Prisma Cloud Compute Image Namespaces",
            "sortable": False,
            "fieldOrder": 62,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "package_name",
            "displayText": "Prisma Cloud Compute Image Package Name",
            "sortable": False,
            "fieldOrder": 63,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "package_version",
            "displayText": "Prisma Cloud Compute Image Package Version",
            "sortable": False,
            "fieldOrder": 64,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ransomwareFamily",
            "displayText": "Ransomware Family",
            "sortable": False,
            "fieldOrder": 65,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "resolvedOn",
            "displayText": "Resolved On",
            "sortable": False,
            "fieldOrder": 66,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "resourceCpe",
            "displayText": "Resource CPE",
            "sortable": False,
            "fieldOrder": 67,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerName",
            "displayText": "Scanner Name",
            "sortable": False,
            "fieldOrder": 68,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerOutput",
            "displayText": "Scanner Output",
            "sortable": False,
            "fieldOrder": 69,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerPlugin",
            "displayText": "Scanner Plugin",
            "sortable": False,
            "fieldOrder": 70,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "scannerReportedSeverity",
            "displayText": "Scanner Reported Severity",
            "sortable": False,
            "fieldOrder": 71,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "severity",
            "displayText": "Severity",
            "sortable": False,
            "fieldOrder": 72,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "severityGroup",
            "displayText": "Severity Group",
            "sortable": False,
            "fieldOrder": 73,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "severityOverride",
            "displayText": "Severity Override",
            "sortable": False,
            "fieldOrder": 74,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "status",
            "displayText": "Status",
            "sortable": False,
            "fieldOrder": 75,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "tagIds",
            "displayText": "Tag Ids",
            "sortable": False,
            "fieldOrder": 76,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "tags",
            "displayText": "Tags",
            "sortable": False,
            "fieldOrder": 77,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsId",
            "displayText": "Tickets Id",
            "sortable": False,
            "fieldOrder": 78,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsLink",
            "displayText": "Tickets Link",
            "sortable": False,
            "fieldOrder": 79,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "ticketsStatus",
            "displayText": "Tickets Status",
            "sortable": False,
            "fieldOrder": 80,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vrrGroup",
            "displayText": "VRR Group",
            "sortable": False,
            "fieldOrder": 81,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vulnerability",
            "displayText": "Vulnerability",
            "sortable": False,
            "fieldOrder": 82,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "vulnerabilityRiskRating",
            "displayText": "Vulnerability Risk Rating",
            "sortable": False,
            "fieldOrder": 83,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "wascIds",
            "displayText": "WASC ID",
            "sortable": False,
            "fieldOrder": 84,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchCreated",
            "displayText": "Workflow Create Date",
            "sortable": False,
            "fieldOrder": 85,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchCreatedBy",
            "displayText": "Workflow Created By",
            "sortable": False,
            "fieldOrder": 86,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchExpiration",
            "displayText": "Workflow Expiration Date",
            "sortable": False,
            "fieldOrder": 87,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchId",
            "displayText": "Workflow Id",
            "sortable": False,
            "fieldOrder": 88,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchReason",
            "displayText": "Workflow Reason",
            "sortable": False,
            "fieldOrder": 89,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchState",
            "displayText": "Workflow State",
            "sortable": False,
            "fieldOrder": 90,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            },
            {
            "identifierField": "workflowBatchUserNote",
            "displayText": "Workflow State User Note",
            "sortable": False,
            "fieldOrder": 91,
            "selected": True,
            "sortOrder": 0,
            "sortType": "ASC"
            }
        ]
        }
    ],
    "exportInSingleFile": False
    })

    app_findings_req = requests.request("POST", ex_url, headers=headers, data=payload)
    print("\n[+] Status code",app_findings_req.status_code)
    json_object = json.loads(app_findings_req.text)
    exportName = "App_Blackduck"
    gen_id=json_object["id"]
    print("[+] The Job ID is {}\n".format(gen_id))

    print("[+] Waiting for the Job to Complete\n")

    while True:
        status_check = requests.get("https://{}.risksense.com/api/v1/client/{}/export/{}/status".format(platform,clientID,gen_id),headers=headers)
        status_json = json.loads(status_check.text)
        # print(status_json["fileId"])
        if status_json["fileId"] != None and status_json["status"] == "COMPLETE":
            print("[+] Downloading the Report\n")
            # time.sleep(2)
            down_report = requests.get("https://{}.risksense.com/api/v1/client/{}/export/{}".format(platform,clientID,gen_id),headers=headers)
            fileName = "Client_"+str(clientID)
            with open (fileName+".zip", 'wb') as f:
                f.write(down_report.content)
            z = zipfile.ZipFile(fileName+".zip")
            z.extractall("Findings")
            z.close()
            time.sleep(2)            
            #del_report = requests.delete("https://{}.risksense.com/api/v1/client/{}/export/{}".format(platform,clientID,gen_id),headers=headers)
            os.remove(fileName+".zip")
            break
        else:
            time.sleep(10)

def rs_JIRA_fielddata(issuetype_resp_json,VRR_group,CVSS3score,Scanner_Name,flag):
   #print(issuetype_resp_json)
   for i in issuetype_resp_json["fields"]:                
      #print(i)
      if(i["label"] == "Risk Adjusted Severity"):    
            if(VRR_group) == "Critical":
               RAS = i["selectOptions"][0]["displayValue"]
               RAS_val = i["selectOptions"][0]["value"]
            if(VRR_group) == "High":
               RAS = i["selectOptions"][1]["displayValue"]
               RAS_val = i["selectOptions"][1]["value"]
            if(VRR_group) == "Medium":
               RAS = i["selectOptions"][2]["displayValue"]
               RAS_val = i["selectOptions"][2]["value"]
            if(VRR_group) == "Low":
               RAS = i["selectOptions"][3]["displayValue"]
               RAS_val = i["selectOptions"][3]["value"]
            if(VRR_group) == "Info":
               RAS = i["selectOptions"][4]["displayValue"]
               RAS_val = i["selectOptions"][4]["value"]
            if(VRR_group) == "":
               flag = 1
               k = i
      #print(VRR_group)
      if(i["label"] == "CVSS 3 0 Severity"):
            CVSS_sev = ""
            sev_val = ""
            if CVSS3score != "":
               if CVSS3score >= 9.0 and CVSS3score <= 10.0:
                  CVSS_sev = i["selectOptions"][0]["displayValue"]
                  sev_val = i["selectOptions"][0]["value"]
               if CVSS3score >= 7.0 and CVSS3score <= 8.9 :
                  CVSS_sev = i["selectOptions"][1]["displayValue"]
                  sev_val = i["selectOptions"][1]["value"]
               if CVSS3score >= 4.0 and CVSS3score <= 6.9 :
                  CVSS_sev = i["selectOptions"][3]["displayValue"]
                  sev_val = i["selectOptions"][3]["value"]
               if CVSS3score >= 0.1 and CVSS3score <= 3.9 :
                  CVSS_sev = i["selectOptions"][2]["displayValue"]
                  sev_val = i["selectOptions"][2]["value"]
               if CVSS3score == 0.0 :
                  CVSS_sev = i["selectOptions"][4]["displayValue"]
                  sev_val = i["selectOptions"][4]["value"]
               if CVSS3score == "" :
                  pass
            else:
               CVSS3score = ""
               
      if(i["label"] == "Source of Vulnerability"):  
            if("polaris" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][1]["displayValue"]
               Scanner_value = i["selectOptions"][1]["value"]
            elif("blackduck" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][0]["displayValue"]
               Scanner_value = i["selectOptions"][0]["value"]
            elif("prisma" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][2]["displayValue"]
               Scanner_value = i["selectOptions"][2]["value"]
            elif("qualys" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][3]["displayValue"]
               Scanner_value = i["selectOptions"][3]["value"]
            elif("whitehat" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][4]["displayValue"]
               Scanner_value = i["selectOptions"][4]["value"]
            elif("hackerone" in Scanner_Name.lower()):
               Scanner_Name = i["selectOptions"][5]["displayValue"]
               Scanner_value = i["selectOptions"][5]["value"] 
            else:
               Scanner_Name = i["selectOptions"][9]["displayValue"]
               Scanner_value = i["selectOptions"][9]["value"]


   #print(Scanner_Name,Scanner_value)
   #print(CVSS_sev,sev_val)            
   if(flag == 1):
      RAS = CVSS_sev
      RAS_val = sev_val
      #print(j)
      if "Critical" in CVSS_sev: 
            RAS = k["selectOptions"][0]["displayValue"]
            RAS_val = k["selectOptions"][0]["value"]
      elif "High" in CVSS_sev: 
            RAS = k["selectOptions"][1]["displayValue"]
            RAS_val = k["selectOptions"][1]["value"]
      elif "Medium" in CVSS_sev: 
            RAS = k["selectOptions"][2]["displayValue"]
            RAS_val = k["selectOptions"][2]["value"]
      elif "Low" in CVSS_sev: 
            RAS = k["selectOptions"][3]["displayValue"]
            RAS_val = k["selectOptions"][3]["value"]
      elif "Info" in CVSS_sev: 
            RAS = k["selectOptions"][4]["displayValue"] 
            RAS_val = k["selectOptions"][4]["value"]
      elif "" in CVSS_sev: 
            RAS = k["selectOptions"][5]["displayValue"]
            RAS_val = k["selectOptions"][5]["value"] 
   #print(flag)
   #print(RAS,CVSS_sev,sev_val,RAS_val)

   for i in issuetype_resp_json["fields"]:  
      if(i["label"] == "Priority"):
            if(RAS) == "Critical - SLA 2":
               Priority_group = i["selectOptions"][2]["displayValue"]
               val = i["selectOptions"][2]["value"]
            if(RAS) == "High - SLA 30":
               Priority_group = i["selectOptions"][4]["displayValue"]
               val = i["selectOptions"][4]["value"]
            if(RAS) == "Medium - SLA 90":
               Priority_group = i["selectOptions"][4]["displayValue"]
               val = i["selectOptions"][4]["value"]
            if(RAS) == "Low - SLA 180":
               Priority_group = i["selectOptions"][6]["displayValue"]
               val = i["selectOptions"][6]["value"]
            if(RAS) == "Info":
               Priority_group = i["selectOptions"][7]["displayValue"]
               val = i["selectOptions"][7]["value"]
            if(RAS == "Unknown"):
               Priority_group = i["selectOptions"][7]["displayValue"]
               val = i["selectOptions"][7]["value"]


   '''for l in issuetype_resp_json["fields"]:
      if(l["label"] == "Components"): 
        #print(l)
         Comp_id = l["selectOptions"][0]["displayValue"]
         Comp_val = l["selectOptions"][0]["value"]'''

      #print(RAS,RAS_val,CVSS_sev,sev_val,Scanner_Name,Priority_group,val)
   return RAS,RAS_val,CVSS_sev,sev_val,Scanner_Name,Scanner_value,Priority_group,val

def ticket_json(param):
   if(param == "C"):
      SO_field = "customfield_11457"
      RAS_val_field = "customfield_11458"
      CVSS_Sev_val_field = "customfield_11459"
      CVSS3_score_field = "customfield_11460"
      CVSS_vector_field = "customfield_11461"
      CVE_field = "customfield_11462"
      CWE_field = "customfield_11463"
      VRR_field = "customfield_11464"
      CIP_field = "customfield_11455"
      CIP_value_field = "12545"
      CIP_display_field = "Unknown"
      SOV_field = "customfield_11456"

   elif(param == "R"):
      SO_field = "customfield_12012"
      RAS_val_field = "customfield_12013"
      CVSS_Sev_val_field = "customfield_12014"
      CVSS3_score_field = "customfield_12015"
      CVSS_vector_field = "customfield_12016"
      CVE_field = "customfield_12017"
      CWE_field = "customfield_12018"
      VRR_field = "customfield_12019"
      CIP_field = "customfield_12010"
      CIP_value_field = "11636"
      CIP_display_field = "Unknown"
      SOV_field = "customfield_12011"
      

   return SO_field,RAS_val_field,CVSS_Sev_val_field,CVSS3_score_field,CVSS_vector_field,CVE_field,CWE_field,VRR_field,CIP_field,CIP_value_field,CIP_display_field,SOV_field