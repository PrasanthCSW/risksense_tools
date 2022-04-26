# Requirements

*  Use ‘pip3 install -r requirements.txt’ to install all dependencies present in the requirements.txt file.

# Wazuh.sh

* This script is used to pull the data from Splunk and push it to the Risksense Platform

# upload_to_platform\conf\config.toml

Enter the Risksense Platform URL , API key and client ID in config.toml file under "upload_to_platform-master_branch\conf" ; 

* platform = 'https://platform4.risksense.com'
* api-key = 'xxxx'   ---> to be generated in Risksense platform for a user.
* client_id = 12345  --> hovering over your user initials will provide the ID of the current client you are logged into

Once these values are entered, you can run the script as;

Usage:

* sh ./Wazuh.sh "option"

'option' can be , 
"C" - Critical , "H" - High , "M" - Medium or "L" - Low
