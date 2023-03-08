from platform import platform
import requests
import json
from functionCalls import *

def main():

    log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'log', 'BD_logs.logs')
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)    
    logging.basicConfig(filename=log_file, level=logging.DEBUG,format='%(levelname)s:  %(asctime)s > %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

    print("**** STARTING THE BlackDuck JIRA Ticket Creation SCRIPT ****\n")
    logging.info("**** STARTING THE BlackDuck JIRA Ticket Creation SCRIPT ****\n")
    app_name_list = app_level_grouping()
    print(app_name_list)

    for app_name in range(len(app_name_list)):
        jsonified_result = groupby(app_name_list[app_name])
        for scanner_plugin in range(len(jsonified_result["data"])):
            scanner_plugin_name = jsonified_result["data"][scanner_plugin]["App Finding Scanner Plugin"]
            print("\n[+]  Application '{}' , Scanner Plugin '{}' ({}/{}) is being exported for ticket creation...".format(app_name_list[app_name],scanner_plugin_name,scanner_plugin+1,len(jsonified_result["data"])))
            logging.info("\n[+]  Application '{}' , Scanner Plugin '{}' ({}/{}) is being exported for ticket creation...".format(app_name_list[app_name],scanner_plugin_name,scanner_plugin+1,len(jsonified_result["data"])))
            #export(scanner_plugin_name,app_name_list[app_name])

            print("\n[+]  Reading the exported scanner plugin info file...")
            logging.info("\n[+]  Reading the exported scanner plugin info file...")
            try:
                df = pd.read_csv("Findings/Findings.csv", low_memory=False)
                app_list = df["App Name"].values.tolist()
                #print(app_list)
                app_list = "\n".join(app_list)
                location_list = df["Location"].astype(str).str.strip().unique().tolist()
                print(location_list)
                location_list = "\n".join(location_list)
            except pd.errors.EmptyDataError:
                print("\n[+] The exported information is empty")
                logging.error("\n[+] The exported information is empty.")
                print("\n-----------------------------------------------------------------------------------------------------------")
                logging.info("\n-----------------------------------------------------------------------------------------------------------")
                continue

            connectorID = get_connectorDetails(str(connector_name))
            #print(connectorID)
            print("\n[+] Connector ID for \"{}\" is {}".format(connector_name,connectorID))
            logging.info("\n[+] Connector ID for \"{}\" is {}".format(connector_name,connectorID))
            
            df['App Name'] = df['App Name'].replace(np.nan,"Not Available")
            df['Due Date'] = df['Due Date'].replace(np.nan,"Not Available")
            df['Possible Solution'] = df['Possible Solution'].replace(np.nan,"Not Available")
            df['Possible Patches'] = df['Possible Patches'].replace(np.nan,"Not Available")
            df['Description'] = df['Description'].replace(np.nan,"Not Available")
            df['CWE ID'] = df['CWE ID'].replace(np.nan,"Not Available")
            df['Location'] = df['Location'].replace(np.nan,"Not Available")
            df['CVSS 3.0'] = df['CVSS 3.0'].replace(np.nan,"")
            df['CVSS 3.0 Vector'] = df['CVSS 3.0 Vector'].replace(np.nan,"")
            df['OWASP'] = df['OWASP'].replace(np.nan,"Not Available")
            df['Scanner Name'] = df['Scanner Name'].replace(np.nan,"Not Available")
            df['Vulnerability'] = df['Vulnerability'].replace(np.nan,"Not Available")
            df['Vulnerability Risk Rating'] = df['Vulnerability Risk Rating'].replace(np.nan,"") 
            df['VRR Group'] = df['VRR Group'].replace(np.nan,"")
            df['Due Date'] = df['Due Date'].replace(np.nan,"Not Available")
            df['Scanner Output'] = df['Scanner Output'].replace(np.nan,"Not Available")
            df['Scanner Plugin'] = df['Scanner Plugin'].replace(np.nan,"Not Available")
            
            id_list = df["Id"].astype(str).str.strip().unique().tolist()
            #id_list_desc = df["Id"].astype(str).str.strip().unique().tolist()
            id_list = ','.join(id_list)
            #print(type(id_list),id_list)
            TotalAppFindings = df.shape[0]
            print("\n[+] Total Cumulative AppFindings without ticket creation is {}".format(TotalAppFindings))
            logging.info("\n[+] Total AppFindings without ticket creation is {}".format(TotalAppFindings))
            
            userID =  get_userId()
            print("\n[+] User ID is {}".format(userID))
            count = 0
                
            # Iterating through each row to create ticket per finding
            scanner_link_app = str(app_name_list[app_name]).replace(" ","%20")
            for j in range(1):
                CWE = ''
                flag = 0
                id = df.iloc[j]["Id"]
                uniqueVulnerability = df.iloc[j]["Vulnerability"]
                scannerplugin = str(df.iloc[j]["Scanner Plugin"])[10:]
                print(scannerplugin)
                scanner_link = 'https://ivanti.app.blackduck.com/api/vulnerabilities/{}/affected-projects?sortField=project.name%2C%20release.version&ascending=true&offset=0&q={}'.format(scannerplugin,str(scanner_link_app))
                df['CWE ID'] = df['CWE ID'].astype(str)
                CWE_list = df.iloc[j]["CWE ID"].split(",")
                #print(CWE_list)
                if(CWE_list[0] != "" and CWE_list[0] != "Not Available"):
                    for i in CWE_list:
                        CWE += "CWE - " + str(i) + " , "
                else:
                    CWE = "Not Available"

                AppName = df.iloc[j]["App Name"]
                OWASP = df.iloc[j]["OWASP"]
                CVSS3score = df.iloc[j]["CVSS 3.0"]
                CVSS3vector = df.iloc[j]["CVSS 3.0 Vector"]
                VRR = df.iloc[j]["Vulnerability Risk Rating"]
                Due_date = df.iloc[j]["Due Date"]
                
                
                Title = "SID - " + str(id) + " : " + str(uniqueVulnerability)
                SolutionString = df.iloc[j]["Possible Solution"]
                PatchString = df.iloc[j]["Possible Patches"]
                Description = df.iloc[j]["Description"]
                Location = df.iloc[j]["Location"]
                VRR_group = df.iloc[j]["VRR Group"]
                Scanner_Name = df.iloc[j]["Scanner Name"]
                if("polaris" in Scanner_Name.lower()):
                    Scanner_output = df.iloc[j]["Scanner Output"]
                else:
                    Scanner_output = ""

            # Extracting the JIRA fields to populate with the data
            
                headers = {
                "content-type": "application/json",
                "x-api-key": api_key     
                }

                issuetype_resp = requests.get("https://{}.risksense.com/api/v1/client/{}/connector/{}/issueTypeField".format(platform,clientID,connectorID),headers=headers)
                #print(issuetype_resp.text)
                issuetype_resp_json = json.loads(issuetype_resp.text)

            # Iterating through the fields to populate with the data from Risksense
                if("cherwell" in connector_name.lower()):
                    param = "C"
                elif("rs" in connector_name.lower() or "risksense" in connector_name.lower()):    
                    param = "R"
                    

                RAS,RAS_val,CVSS_sev,sev_val,Scanner_Name,Scanner_value,Priority_group,val = rs_JIRA_fielddata(issuetype_resp_json,VRR_group,CVSS3score,Scanner_Name,flag)
                #print(RAS,RAS_val,CVSS_sev,sev_val,Scanner_Name,Scanner_value,Priority_group,val)
                #print(Priority_group,val) 

            # Tag creation and fetch its ID from Risksense
                            
                count = count+1
                tagName = str(id) + "  Dated: " + datetime.date(day=currentDate.day, month=currentDate.month, year=currentDate.year).strftime('%d %B %Y') + " " + currentTime + " Ticket - " + str(count)
                filter_tagCreation = {
                    "fields":[
                        {
                        "uid":"TAG_TYPE",
                        "value":"REMEDIATION"
                        },
                        {
                        "uid":"NAME",
                        "value":tagName
                        },
                        {
                        "uid":"DESCRIPTION",
                        "value":""
                        },
                        {
                        "uid":"OWNER",
                        "value":userID
                        },
                        {
                        "uid":"COLOR",
                        "value":"#648d9f"
                        },
                        {
                        "uid":"LOCKED",
                        "value":False
                        },
                        {
                        "uid":"PROPAGATE_TO_ALL_FINDINGS",
                        "value":True
                        }
                    ]
                    }

                tagCreation_resp = requests.post("https://{}.risksense.com/api/v1/client/{}/tag".format(platform,clientID),headers=headers,json=filter_tagCreation)
                if tagCreation_resp.status_code == 201:
                    tagCreation_resp_json = json.loads(tagCreation_resp.text)
                    tagID = tagCreation_resp_json['id']
                    print("\n[+] Form for the ticket creation has been filled and tag is created Successfully!. The Tag ID is: {}".format(tagID))
                    logging.info("\n[+] Form for the ticket creation has been filled and tag is created Successfully!. The Tag ID is: {}".format(tagID))
                    
                else:
                    print("\n[+] Failure!, tag is not created. Reason : {}".format(tagCreation_resp.text))
                    
                    logging.error("\n[+] Failure!, tag is not created. Reason : {}".format(tagCreation_resp.text))

            # Ticket creation in JIRA with the fields from RS
            

                SO_field,RAS_val_field,CVSS_Sev_val_field,CVSS3_score_field,CVSS_vector_field,CVE_field,CWE_field,VRR_field,CIP_field,CIP_value_field,CIP_display_field,SOV_field = ticket_json(param)

                filter_ticketCreation = {"connectorId":connectorID,"dynamicFields":[{"key":SO_field,"value":str(scanner_link),"displayValue":str(scanner_link)},{"key":RAS_val_field,"value":str(RAS_val),"displayValue":str(RAS)},{"key":CVSS_Sev_val_field,"value":str(sev_val),"displayValue":str(CVSS_sev)},{"key":"priority","value":str(val),"displayValue":str(Priority_group)},{"key":"summary","value":str(Title),"displayValue":""},{"key":CVSS3_score_field,"value":str(CVSS3score),"displayValue":""},{"key":CVSS_vector_field,"value":str(CVSS3vector),"displayValue":""},{"key":CVE_field,"value":"","displayValue":""},{"key":CWE_field,"value":str(CWE),"displayValue":""},{"key":VRR_field,"value":str(VRR),"displayValue":""},{"key":"description","value":str(Description),"displayValue":""},{"key":CIP_field,"value":CIP_value_field,"displayValue":CIP_display_field},{"key":SOV_field,"value":str(Scanner_value),"displayValue":str(Scanner_Name)}],"type":"JIRA","slaDateField":"","usePluginInfoFields":[],"publishTicketStats":False}

                ticketCreation_resp = requests.post("https://{}.risksense.com/api/v1/client/{}/ticket/{}".format(platform,clientID,tagID),headers=headers,json=filter_ticketCreation)
                #print(ticketCreation_resp.status_code)
                if ticketCreation_resp.status_code == 200:
                    ticketCreation_resp_json = json.loads(ticketCreation_resp.text)
                    ticketID = ticketCreation_resp_json["ticketId"]
                    print("\n[+] The ticket is created for the application {} JIRA and for the scanner plugin {} in the instance {}.".format(app_name_list[app_name],scanner_plugin_name,instance))
                    logging.info("\n[+] The ticket is created for the application {} JIRA and for the scanner plugin {} in the instance {}.".format(app_name_list[app_name],scanner_plugin_name,instance))
                else:
                    print("\n[+] Failure!, Ticket is not created in the instance")
                    logging.error("\n[+] Failure!, Ticket is not created in the instance")
                    break

            # Tag assignment in RS and sync its value with JIRA field    

                filter_ticketAttachment = {"tagId":tagID,"isRemove":False,"filterRequest":{"filters":[{"field":"id","exclusive":False,"operator":"IN","value":id_list}]},"publishTicketStats":True}

                ticketAttachment_resp =  requests.post("https://{}.risksense.com/api/v1/client/{}/search/applicationFinding/job/tag".format(platform,clientID),headers=headers,json=filter_ticketAttachment)
                if ticketAttachment_resp.status_code == 200:
                    print("\n[+] Attachment is attached in the created ticket successfully!")
                    logging.info("\n[+] Attachment is attached in the created ticket successfully!")
                else:
                    print("\n[+] Failure!, Attachment is not attached in the created ticket. Reason : {}".format(ticketAttachment_resp.text))
                    logging.error("\n[+] Failure!, Attachment is not attached in the created ticket. Reason : {}".format(ticketAttachment_resp.text))
                    break

            # Extended Description attachment in JIRA
                    
                filter_TitleDescription = {
                    "version": 1,
                    "type": "doc",
                    "content": [
                    ]
                }
                
                vuln_name_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Vulnerability",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                vuln_name = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": uniqueVulnerability
                    }
                    ]
                }
                
                Des_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Description",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                Description = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": Description
                    }
                    ]
                }
                Scanner_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Scanner Name",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }

                Scanner_name = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": Scanner_Name
                    }
                    ]
                }
                
                Location_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Location",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                Location = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": str(location_list)
                    }
                    ]
                }
                App_name_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Applications Affected",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                App_name = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": str(app_list)
                    }
                    ]
                }
                CWE_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "CWE ID's",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }

                CWE = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": CWE
                    }
                    ]
                }
                
                OWASP_title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "OWASP Category",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                OWASP = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": OWASP
                    }
                    ]
                }
                base_Solution_Title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Possible Solution",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }        
                base_Solution = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": SolutionString
                    }
                    ]
                }
                base_Patch_Title = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": "Possible Patch",
                    "marks": [
                        {
                        "type": "strong"
                        }
                    ]
                    }
                    ]
                }
                base_Patch = {
                    "type": "paragraph",
                    "content": [
                    {
                    "type": "text",
                    "text": PatchString
                    }
                    ]
                }

                filter_TitleDescription["content"].extend([vuln_name_title,vuln_name,Des_title,Description,Scanner_title,Scanner_name,Location_title,Location,App_name_title,App_name,CWE_title,CWE,OWASP_title,OWASP,base_Solution_Title,base_Solution,base_Patch_Title,base_Patch])
                #print(filter_TitleDescription)

                titleDescription_resp = requests.put("https://{}/rest/internal/3/issue/{}/description".format(instance,ticketID),auth=(user, password),json=filter_TitleDescription)
                
                if titleDescription_resp.status_code == 204:
                    print("\n[+] Description of the ticket is overwritten SUCCESSFULLY!")
                    print("\n[+] Ticket {} is created and the extended description is written!".format(ticketID))

                    logging.info("\n[+] Description of the ticket is overwritten SUCCESSFULLY!")
                    logging.info("\n[+] Ticket {} is created and the extended description is written!".format(ticketID))

                else:
                    print("\n[+] Failure!, Description of the ticket is not overwritten. Please check the config.xlsx file. Reason : {}".format(titleDescription_resp.text))
                    logging.error("\n[+] Failure!, Description of the ticket is not overwritten. Please check the config.xlsx file. Reason : {}".format(titleDescription_resp.text))

                headers = {
                    'X-Atlassian-Token': 'no-check',
                }
                files = {
                    'file': open('Findings/Findings.csv', 'rb'),
                }

                response = requests.post(
                    'https://{}/rest/api/2/issue/{}/attachments'.format(str(instance),str(ticketID)),
                    headers=headers,
                    files=files,
                    auth=(user,password),
                )
                #print(response.text,response.status_code)

                if response.status_code == 200:
                    print("\n[+] File {}  is attached in the created ticket successfully!".format('Findings/Findings.csv'))
                    logging.info("\n[+] File {}  is attached in the created ticket successfully!".format('Findings/Findings.csv'))
                    print("------------------------------------------------------------")
                    logging.info("------------------------------------------------------------")

                else:
                    print("\n[+] Failure!, Attachment is not attached in the created ticket. Reason : {}".format(response.text))
                    logging.error("\n[+] Failure!, Attachment is not attached in the created ticket. Reason : {}".format(response.text))
                    print("------------------------------------------------------------")
                    logging.info("------------------------------------------------------------")

                    break


if __name__ == "__main__":
    main()

