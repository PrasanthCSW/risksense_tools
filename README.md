# risksense_tools

A repository of tools that interact with the RiskSense API.

## Available Tools

* **appfinding_report_from_saved_filter**
  * A tool for generating a csv report based upon a saved filter in the platform.
* **tag_import_tool**
  * A tool for the mass creation of new tags via the reading of a .csv file.
* **cmdb_update_tool**
  * A tool for the mass update of hosts' CMDB information via the reading of a .csv file.
* **group_import_tool**
  * A tool for the mass creation of new groups via the reading of a .csv file.
* **hostfinding_report_from_saved_filter**
  * A tool for generating a csv report based upon a saved filter in the platform.
* **asset_criticality_update**
  * A tool for updating assets' criticalities via reading of a csv file.
* **create_and_assigntags**
  * A tool used to create remediation and assign host findings tags
* **burpsuite_create**
  * A tool used to create burpsuite connector
* **delete_hosts_in_defaultgroup**
  * A tool that is used to delete the hosts data from default group
* **deletes_app_sindefaultgroup**
  * A tool that is used to delete apps in default group
* **Groupbyexport**
  * A tool that is used to export data in groupby
* **hclappscan_connector_create**
  A tool used to create hcl appscan connector
* **jira_connector_create**
  A tool for creating a JIRA connector in Risksense platform.
* **nessus_create**
  A tool for creating nessus connectors in product/demo risksense platforms
* **nexposeconnector create**
  A tool for creating nexpose connectors in product/demo risksense platforms
* **qualyspcconnector_create**
  A tool for creating qualys policy compliance connectors in product/demo risksense platforms
* **qualysvm_create**
  A tool for creating qualys vmdr connector connectors in product/demo risksense platforms
* **qualysvulnconnector_create**
  A tool for creating qualys vulnerability connectors in product/demo risksense platforms
* **qualyswasconnector_create**
  A tool for creating qualys web application connectors in product/demo risksense platforms
* **rs3simulator**
  A tool for simulating rs3 score for assets in risksense
* **slacreation**
  A tool for creating sla in platform
* **exportslahf**
  A tool for exporting hostfindings that based on sla in platform
* **slapriority**
  A tool for getting priority of a particular sla in platform
* **snow_incident_connector_create**
  A tool for creating a Service Now Incident type connector in Risksense platform.
* **sonarcloudconnector_create**
  A tool for creating sonar cloud connectors in product/demo risksense platforms

## Test Cases

## Requirements
* A working [Python 3](https://python.org) installation is required.
* Additionally, the following Python packages are required:
  * [TOML](https://pypi.org/project/toml/)
  * [Requests](https://pypi.org/project/requests/)
  * [Progressbar2](https://pypi.org/project/progressbar2/)
  * [rich](https://pypi.org/project/rich/)
  
The required packages can be installed with the following command:

    pip install -r requirements.txt

***Or***, depending on your installation of Python/Pip:

    pip3 install -r requirements.txt


## Installation
Download zip file, copy the file to the desired location, and unzip.
