#usr/bin/python
import getIssues
import os
import sys
import csv
import shutil
import toml
import logging
import argparse
import requests
from requests.structures import CaseInsensitiveDict
import json
import subprocess
import datetime


pi,pe,pn,bi,be,bn = [],[],[],[],[],[]
pic = pec = pnc = bic = bec = bnc = 0
def read_config_file(filename):
    
    try:
        toml_data = open(filename).read()
        data = toml.loads(toml_data)
       
    except FileNotFoundError:
        print("Wrong file or file path (or) Config file does not exist")
        logging.info("Wrong file or file path (or) Config file does not exist")
    return data
 
def get_all_projects(jwt):

    url = "https://ivanti.polaris.synopsys.com/api/common/v0/projects?page%5Blimit%5D=1000&page%5Boffset%5D=0"
    payload={}
    headers = {
      'Authorization': 'Bearer ' + jwt
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    try:
        json_data = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("String could not be converted to JSON")
        logging.info("String could not be converted to JSON")
        return pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
    return json_data

def extract_upload(Condition,token,project,branch,file):
    
    global pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
    if(Condition == "C"):
        param = "--closed"
        print("==================================================== Getting Closed Issues for {0} project and {1} branch ====================================================\n".format(project,branch))
        logging.info("==================================================== Getting Closed Issues for {0} project and {1} branch ====================================================\n".format(project,branch))
    elif(Condition == "O"):
        param = "--opened" 
        print("==================================================== Getting Opened Issues for {0} project and {1} branch ====================================================\n".format(project,branch))   
        logging.info("==================================================== Getting Opened Issues for {0} project and {1} branch ====================================================\n".format(project,branch))        
    elif(Condition == "A"):
        param = "--all" 
        print("==================================================== Getting All Issues for {0} project and {1} branch ====================================================\n".format(project,branch))
        logging.info("==================================================== Getting All Issues for {0} project and {1} branch ====================================================\n".format(project,branch))
        
    try:
        os_cmd = "python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token \"%s\" --project \"%s\" --branch \"%s\" \"%s\" --csv  > \"%s\".csv" % (token,project,branch,param,file)
        if os.system(os_cmd) != 0:
            raise Exception('There might be some issues with the runs for the project\'s branch....')
    except:
        pe.append(project)
        pec+=1
        be.append(branch)
        bec+=1
        print("There might be some issues with the project\'s branch (or) There might be no runs for the project, Please Check in Polaris GUI")
        logging.info("There might be some issues with the project\'s branch (or) There might be no runs for the project, Please Check in Polaris GUI")
        return pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
  
    file1 = open(file+".csv")
    content = file1.readlines()
    file1.close()
    if("noissues" in content[0]):
        pn.append(project)
        bn.append(branch)
        pnc+=1
        bnc+=1
        print("The defined spec doesn't have any issues")
        logging.info("The defined spec doesn't have any issues")   
        os.remove(file+".csv")
    elif("FATAL" in content[0]):
        pass
    else:
        shutil.copy(file+".csv", 'upload_to_platform/files_to_process')
        os.remove(file+".csv")
        pi.append(project)
        bi.append(branch)
        pic+=1
        bic+=1
        execution3 = "python upload_to_platform/upload_to_platform.py"
        os.system(execution3)
        
       
    return pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
    
def getJwt(token):
    
    headers = {
        'accept': 'application/json',
    }
    data = {
        'accesstoken': token,
    }
    response = requests.post('https://ivanti.polaris.synopsys.com/api/auth/v1/authenticate', headers=headers, data=data)
    json_data = json.loads(response.text)
    return json_data["jwt"]

def getBranches_runs(branch_link):
    endpoint = branch_link + "?page%5Blimit%5D=1000&page%5Boffset%5D=0"
    payload={}
    headers = {
      'Authorization': 'Bearer ' + jwt
    }
    response = requests.request("GET", endpoint, headers=headers, data=payload)
    try:
        json_data = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("String could not be converted to JSON")
        logging.info("String could not be converted to JSON")
        return pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
    return json_data
    

def getbranchName(branchId,baseUrl):
    endpoint = baseUrl + '/api/common/v0/branches/' + branchId
    payload={}
    headers = {
      'Authorization': 'Bearer ' + jwt
    }
    response = requests.request("GET", endpoint, headers=headers, data=payload)
    try:
        json_data = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("String could not be converted to JSON")
        logging.info("String could not be converted to JSON")
        return pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc
    return json_data["data"]["attributes"]["name"]
    
if __name__ == '__main__':

    Condition = sys.argv[1]  
    log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'log', 'polaris.log')
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)    
    logging.basicConfig(filename=log_file, level=logging.DEBUG,format='%(levelname)s:  %(asctime)s > %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    conf_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'conf', 'config_polaris.toml')
    logging.info("***** STARTING Polaris Ingestion Script *****\n")
    print("***** STARTING Polaris Ingestion Script *****\n")
    configuration = read_config_file(conf_file)
    token = configuration['polaris']['token']
    jwt = getJwt(token)
    url = "https://ivanti.polaris.synopsys.com"
    all_projects = get_all_projects(jwt)
    print("\nThe Number of Projects in the instance\n",all_projects["data"])
    for j in range(len(all_projects["data"])):
        file = configuration['polaris']['file']
        project = all_projects["data"][j]["attributes"]["name"]
        branch_link = all_projects["data"][j]["relationships"]["branches"]["links"]["self"]
        all_branches = getBranches_runs(branch_link)
        if(len(all_branches["data"])) == 0:
            print("\nThe project {0} doesn't have any branches\n".format(project))    
        for k in range(len(all_branches["data"])):
            branch_id = all_branches["data"][k]["id"]
           
            branch_name = getbranchName(branch_id,url)
            
            pi,pic,pe,pec,pn,pnc,bi,bic,be,bec,bn,bnc = extract_upload(Condition,token,project,branch_name,file)
     
            print("\n***** The Ingestion is Done *****\n")
            
            print("The Number of Project-Branch Combination ingested : {0}".format(pic))
            
            for c in range(len(bi)):
                print("\t| "+ pi[c] + " - " + bi[c])
                logging.info("\t| "+ pi[c] + " - " + bi[c])
    
            print("\n\nThe Number of Project-Branch combination that got exception : {0}".format(pec))
            
            for a in range(len(pe)):
                print("\t| "+ pe[a] + " - " + be[a])
                
            print("\nThe Number of Project-Branch combination that has no issues : {0}".format(pnc))
            
            for b in range(len(pn)):
                print("\t| "+ pn[b] + " - " + bn[b])
            print("\n")
            
    logging.info("\n***** The Ingestion is Done *****\n")
    logging.info("\nThe Number of Project-Branch Combination ingested : {0}\n".format(pic))
    logging.info("\t| "+ pi[c] + " - " + bi[c])
    logging.info("\n\nThe Number of Project-Branch combination that got exception : {0}".format(pec))
    logging.info("\t| "+ pe[a] + " - " + be[a])
    logging.info("\nThe Number of Project-Branch combination that has no issues : {0}".format(pnc))
    logging.info("\t| "+ pn[b] + " - " + bn[b])    
        
    
