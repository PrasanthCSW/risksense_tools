# cmdb_update
A Python script for updating a series of hosts' CMDB information by reading the information from a .csv file.

## Requirements
A working Python 3 installation is required.  This script has been tested using Python 3.7.2.

The `risksense_api_python` module is required.


## Configuration
#### CSV file
An example .csv file has been provided in this folder. There should be one row per host. __Do not edit the headers of this file.__

##### Column Names:
 * `host` (Host IP Address or hostname.)
 * `os` (Operating System)
 * `manufacturer` (Manufactured By)
 * `model_id` (Model)
 * `location` (Location)
 * `managed_by` (Managed By)
 * `owned_by` (Owned By)
 * `supported_by` (Supported By)
 * `support_group` (Support Group)
 * `sys_updated_on` (Last Scanned)
 * `asset_tag` (Asset tag(s))
 * `mac_address` (Mac Address)
 * `ferpa` (FERPA Compliance Asset)
 * `hipaa` (HIPAA Compliance Asset)
 * `pci` (PCI Compliance Asset)
 * `sys_id` (Unique Id)
 * `cf_1` (Custom Field 1)
 * `cf_2` (Custom Field 2)
 * `cf_3` (Custom Field 3)
 * `cf_4` (Custom Field 4)
 * `cf_5` (Custom Field 5)
 * `cf_6` (Custom Field 6)
 * `cf_7` (Custom Field 7)
 * `cf_8` (Custom Field 8)
 * `cf_9` (Custom Field 9)
 * `cf_10` (Custom Field 10)

#### Script
Near the top of the `update_cmdb.py` file, locate the configuration area as shown below.  
* Update the `PLATFORM_URL` variable value to reflect the RiskSense platform you use.
* Update the `API_KEY` variable value to reflect your API key.  You can generate an API key from the User Settings page
  in the RiskSense platform UI.
* If you are a single-client user, there is no need to update the `CLIENT_ID` variable value.  If you are a multi-client
  user, you will need to edit the `CLIENT_ID` variable value to reflect the ID of the client you wish to work with.
* Update the `CMDB_CSV_FILENAME` variable value to reflect the path to your .csv file.
* Update the `NETWORK_TYPE` variable to reflect whether you are going to be providing IP addresses or hostnames
  in your .csv file to identify hosts.

```python
# ==== BEGIN CONFIGURATION ============================================================================================

#  URL for your platform.
PLATFORM_URL = 'https://platform.risksense.com'

#  Your API key.  Can be generated on your user settings page when logged in to the RiskSense platform.
API_KEY = ''

#  If you are a single-client user, there is no need to edit the CLIENT_ID variable.
#  If you are a multi-client user, specify the client ID you wish to work with here.
#  Example:
#  CLIENT_ID = 12345
CLIENT_ID = None

#  Path to CSV file to read CMDB info from.
CMDB_CSV_FILENAME = 'csv_file_example.csv'

# Define network type.  Valid options are 'IP' or 'HOSTNAME'.
NETWORK_TYPE = 'IP'

#  No need to edit the line below.
PROFILE = risksense_api_python.Profile('user_profile', PLATFORM_URL, API_KEY)

# ==== END CONFIGURATION ==============================================================================================
```

## Execution
Once you have completed configuration of the script, and completed your .csv file, the script can be run from your
terminal as follows:

```commandline

python3 update_cmdb.py

 -- OR (depending on your installation) --

python update_cmdb.py

```