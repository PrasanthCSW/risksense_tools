## Requirements

 - Python 3
    - This script has been tested using Python 3.7
 - Python Modules (recommend to install using pip):
    - toml
    - urllib3
    - requests
    - progressbar2
    - zipfile
    - datetime
	- json
	- time
	- os
	
	
# upload to platform

Usage :
Pre - requisites :

* Provide the necessary parameters in the conf/config_upload.toml file , which are :
	* Platform 
	* Api Key
	* Network ID
	* Client ID

Run : python upload_to_platform.py

Outcome : The scan results will be uploaded to the intended platform and the client. Once this is run , the data can be exported from Riksense by,

# Export_RS_application_findings
This is to export the Risksense Application findings using RS API's

**Steps to export the results**

* Provide the necessary parameters in config_export.toml file under conf/config_export.toml.
  * Platform
  * API key
  * Client ID
  * Assessment name
  * File name to export
* Run the export_findings.py.

Usage: python export_findings.py 

* You will see that the scan results with Assets and Findings will be placed in a folder with the current date
