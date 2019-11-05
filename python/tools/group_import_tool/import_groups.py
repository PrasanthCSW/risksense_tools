""" *******************************************************************************************************************
|
|  Name        :  import_groups.py.py
|  Description :  Mass creation of groups in the RiskSense platform.
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
GROUP_CSV_FILENAME = 'csv_file_example.csv'

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


def create_group(group_name, asset_criticality):

    """
    Create a new group.

    :param group_name:          Group Name
    :type  group_name:          str

    :param asset_criticality:   Default asset criticality for this new group
    :type  asset_criticality:   int

    :return:    Group ID
    :rtype:     int

    :raises:    ValueError
    :raises:    RequestFailed
    """

    groups = risksense_api_python.Groups(PROFILE, CLIENT_ID)

    if group_name == "" or group_name is None:
        raise ValueError("Exception. Group Name required.")
    if asset_criticality == "" or asset_criticality is None:
        raise ValueError("Exception. Asset criticality required.")

    try:
        group_id = groups.create(group_name, int(asset_criticality))
    except RequestFailed:
        raise

    return group_id


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
    csv_data_dict = read_csv_file(GROUP_CSV_FILENAME)

    #  Submit group creation for each item from .csv file
    for item in csv_data_dict:
        try:
            group_id = create_group(item['group_name'], int(item['asset_criticality']))
            print(f"New group \"{item['group_name']}\" created as group ID {group_id}")
        except RequestFailed:
            print(f"There was an error trying to create new group \"{item['group_name']}\".")
        except ValueError as ve:
            print(ve)


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
