""" *******************************************************************************************************************
|
|  Name        :  update_cmdb.py
|  Description :  Mass-update CMDB fields for hosts based on values in a .csv file.
|  Project     :  risksense_tools
|  Copyright   :  (c) RiskSense, Inc. 
|  License     :  Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
|
******************************************************************************************************************* """

import sys
import csv

import risksense_api_python
from risksense_api_python import RequestFailed


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

#  Path to CSV file to read tag info from.
CMDB_CSV_FILENAME = 'csv_file_example.csv'

# Define network type.  Valid options are 'IP' or 'HOSTNAME'.
NETWORK_TYPE = 'IP'

#  No need to edit the line below.
PROFILE = risksense_api_python.Profile('user_profile', PLATFORM_URL, API_KEY)

# ==== END CONFIGURATION ==============================================================================================


def validate_client_id():

    """
    Validate the supplied CLIENT_ID variable

    :return:    Validity of CLIENT ID supplied
    :rtype:     bool

    :raises:    RequestFailed
    """
    validity = False

    clients = risksense_api_python.Clients(PROFILE)

    try:
        my_clients = clients.get_clients(page_size=300, page_number=0)
    except RequestFailed:
        print(f"Unable to retrieve your client IDs for validation using profile: {PROFILE}.")
        print("Exiting.")
        sys.exit(1)

    my_clients = my_clients['_embedded']['clients']

    for client in my_clients:
        if client['id'] == CLIENT_ID:
            validity = True

    return validity


def get_client_id():

    """
    Get the client ID associated with this API key.

    :return:    Client ID
    :rtype:     int

    :raises:    RequestFailed
    """

    clients = risksense_api_python.Clients(PROFILE)

    try:
        my_client = clients.get_clients(page_size=1, page_number=0)
    except RequestFailed:
        print(f"Unable to retrieve client ID using profile: {PROFILE}.")
        print("Exiting.")
        sys.exit(1)

    client_id = my_client['id']

    return client_id


def read_csv_file(filename):

    """
    Read the CSV file, and convert it to a dict.

    :param filename:    Path to csv file to be read.
    :type  filename:    str

    :return:    The data contained in the csv file, in dict format.
    :rtype:     dict
    """

    return_data = []

    input_file = csv.DictReader(open(filename))

    for row in input_file:
        new_row = {}
        for item in row:
            new_row[item] = row[item]
        return_data.append(new_row)

    return return_data


def send_update_request(**kwargs):

    """
    :keyword host:                  Host                (str)
    :keyword os:                    Operating System.   (str)
    :keyword manufacturer:          Manufacturer.       (str)
    :keyword model_id:              Model.              (str)
    :keyword location:              Location.           (str)
    :keyword managed_by:            Managed By.         (str)
    :keyword owned_by:              Owned By.           (str)
    :keyword supported_by:          Supported By.       (str)
    :keyword support_group:         Support Group.      (str)
    :keyword sys_updated_on:        Last Scanned On.    (str)
    :keyword asset_tag:             Asset Tag.          (str)
    :keyword mac_address:           MAC Address.        (str)
    :keyword ferpa:                 FERPA Compliance    (str)
    :keyword hippa:                 HIPPA Compliance    (str)
    :keyword pci:                   PCI Compliance      (str)
    :keyword sys_id:                System ID           (str)
    :keyword cf_1:                  Custom Field 1      (str)
    :keyword cf_2:                  Custom Field 2      (str)
    :keyword cf_3:                  Custom Field 3      (str)
    :keyword cf_4:                  Custom Field 4      (str)
    :keyword cf_5:                  Custom Field 5      (str)
    :keyword cf_6:                  Custom Field 6      (str)
    :keyword cf_7:                  Custom Field 7      (str)
    :keyword cf_8:                  Custom Field 8      (str)
    :keyword cf_9:                  Custom Field 9      (str)
    :keyword cf_10:                 Custom Field 10     (str)
    :keyword asset_criticality:     Asset Criticality   (int)

    :return:    Job ID
    :rtype:     int

    :raises:    RequestFailed
    :raises:    ValueError
    """

    platform_hosts = risksense_api_python.Hosts(PROFILE, CLIENT_ID)

    # store the host info in a new variable, and pop it from the kwargs dict
    host = kwargs.get('host', None)
    kwargs.pop('host')

    # Create a new dict for the fields to update
    update_dict = {}

    empty_string = ""

    # Populate the new dict using only the columns that are populated for this host
    for item in kwargs:
        if kwargs[item] != empty_string:
            update_dict[item] = kwargs[item]

    if NETWORK_TYPE.upper() == 'HOSTNAME':
        search_filter = [
            {
                "field": "hostname",
                "exclusive": False,
                "operator": "EXACT",
                "value": host
            }
        ]
    else:
        search_filter = [
            {
                "field": "ipAddress",
                "exclusive": False,
                "operator": "EXACT",
                "value": host
            }
        ]

    # If host isn't blank, build the body, and make the API update request
    if host != empty_string and host is not None:
        # Send API update request
        try:
            job_id = platform_hosts.update_hosts_cmdb(search_filter, **update_dict)
        except RequestFailed as rf:
            print(rf)
            raise
    else:
        raise ValueError("There was no host provided for this row.")

    return job_id


def main():

    """ Main body of script """

    global CLIENT_ID

    #  Get client id, or validate supplied client ID
    if CLIENT_ID is None:
        CLIENT_ID = get_client_id()
    else:
        client_validity = validate_client_id()
        if client_validity is False:
            print(f"Unable to validate that you belong to client ID {CLIENT_ID}.")
            print("Exiting.")
            sys.exit(1)

    #  Read CSV file, and convert data to a dict.
    csv_data_dict = read_csv_file(CMDB_CSV_FILENAME)
    total_items = len(csv_data_dict)

    print()
    print(f"{total_items} items found in the .csv file.")
    if total_items == 0:
        print("Exiting...")
        exit(1)

    success_counter = 0
    failure_counter = 0

    print()

    # Loop through each row in the csv data and request an update for each one.
    for item in csv_data_dict:
        # Submit update request to RiskSense
        try:
            job_id = send_update_request(**item)
            print(f"Update request for {item['host']} successfully submitted as job {job_id}.")
            success_counter += 1
        except RequestFailed as rf:
            print(rf)
            failure_counter += 1
        except ValueError as ve:
            print(ve)
            failure_counter += 1

    print()
    print("** DONE **")
    print(f" -- {success_counter}/{total_items} items processed reported successful submission.")
    print(f" -- {failure_counter}/{total_items} items processed did *NOT* report successful submission.")


#
#
#  Execute the script
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("KeyboardInterrupt detected.  Exiting...")
        print()
        sys.exit(0)


"""
   Copyright 2019 RiskSense, Inc.
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
   
   http://www.apache.org/licenses/LICENSE-2.0
   
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
