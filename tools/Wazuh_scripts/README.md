# Requirements

*  Use ‘pip3 install -r requirements.txt’ to install all dependencies present in the requirements.txt file.

# Wazuh.sh

* This script is used to pull the data from Splunk and push it to the Risksense Platform


# upload_to_platform\conf\config.toml

Enter the Risksense Platform URL and API key in config.toml file under "upload_to_platform-master_branch\conf" ; 

* https://platform4.risksense.com 
* API Key - 'xxxx'   ---> to be generated in Risksense platform for a user.


Once these values are entered, you can run the script as;

Usage:

* sh ./Wazuh.sh <option>

'option' can be , 
"C" - Critical , "H" - High , "M" - Medium or "L" - Low

