""" *******************************************************************************************************************
|
|  Name        :  asset_criticality_update.py
|  Project     :  Asset Criticality Update
|  Description :  A tool to update Asset Criticality values based on values designated in a CSV file.
|  Copyright   :  2021 RiskSense, Inc.
|  License     :  Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
|
******************************************************************************************************************* """

import logging
import os
import sys
import csv
import progressbar
import toml
from rich import print
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'lib'))
import risksense_api as rs_api


class AssetCriticalityUpdate:

    """ AssetCriticalityUpdate class """

    def __init__(self, config):

        """
        Main body of script.

        :param config:      Configuration
        :type  config:      dict
        """

        logging.info("***** SCRIPT START ***************************************************")

        #  Set variables
        self._rs_platform_url = config['platform_url']
        api_key = config['api_key']
        self.__client_id = config['client_id']
        self.file_to_read = config['file_to_read']

        try:
            print()
            print(f"Attempting to talk to RiskSense platform {self._rs_platform_url}")
            self.rs = rs_api.RiskSenseApi(self._rs_platform_url, api_key)
            self.rs.set_default_client_id(self.__client_id)
            print("[green] - Success[/green]")
        except (rs_api.UserUnauthorized, rs_api.InsufficientPrivileges,
                rs_api.MaxRetryError, rs_api.StatusCodeError) as ex:
            message = "An error has occurred while trying to verify RiskSense credentials and connection"
            logging.error(message)
            logging.error(ex)
            print()
            print(f"[red bold]{message}. Exiting.[/red bold]")
            exit(1)

        #  Read the CSV file.
        print()
        print("Attempting to read CSV file")
        self._csv_file_contents = self.read_csv_file()
        print(f" - {len(self._csv_file_contents)} found")

        #  If there are no rows in the CSV file found, exit.
        if len(self._csv_file_contents) == 0:
            print("Exiting.")
            exit(0)

        #  Begin sending updates to RiskSense for each host in the CSV file
        print()
        print("Sending update to RiskSense")
        prog_counter = 0
        prog_bar = progressbar.ProgressBar(max_value=len(self._csv_file_contents))

        for host in self._csv_file_contents:
            self.set_asset_criticality(host['hostname'], host['criticality'])
            prog_counter += 1
            prog_bar.update(prog_counter)

        prog_bar.finish()

        print()
        print("Done.")
        print()

        logging.info("***** SCRIPT COMPLETE*************************************************")

# ---------------------------------------------------------------------------------------------------------------------

    def set_asset_criticality(self, hostname, criticality):

        search_filters = [
            {
                "field": "hostName",
                "exclusive": False,
                "operator": "EXACT",
                "value": hostname
            }
        ]

        try:
            job_id = self.rs.hosts.update_hosts_attrs(search_filters, criticality=int(criticality))
            message = f"Successfully submitted update of criticality to {criticality} for host \"{hostname}\" as job {job_id}"
            logging.info(message)
        except (rs_api.UserUnauthorized, rs_api.InsufficientPrivileges,
                rs_api.MaxRetryError, rs_api.StatusCodeError, rs_api.NoMatchFound) as known_ex:
            message = f"An error has occurred while trying to set criticality to {criticality} for host \"{hostname}\""
            logging.error(message)
            logging.error(known_ex)
        except Exception as ex:
            message = f"An unexpected error has occurred while trying to set criticality to {criticality} for host \"{hostname}\""
            logging.error(message)
            logging.error(ex)

    def read_csv_file(self):

        """
        Read the CSV file, and return a list of dicts representing each row's contents

        :return:    A list of dicts representing each row's contents
        :rtype:     list
        """

        file_contents = []

        try:
            with open(self.file_to_read, 'r') as data:
                for line in csv.DictReader(data):
                    file_contents.append(dict(line))
        except FileNotFoundError as fnfe:
            message = "CSV file not found. Exiting."
            logging.error(message)
            logging.error(fnfe)
            print()
            print(f"[bold red]{message}[/bold red]")
            exit(1)
        except Exception as ex:
            message = "An exception has occurred while trying to read the CSV file. Exiting."
            logging.error(message)
            logging.error(ex)
            print()
            print(f"[bold red]{message}[/bold red]")
            exit(1)

        return file_contents

# ---------------------------------------------------------------------------------------------------------------------


def read_config_file(filename):

    """
    Reads a TOML-formatted configuration file.

    :param filename:    Path to the TOML-formatted file to be read.
    :type  filename:    str

    :return:  Values contained in config file.
    :rtype:   dict
    """

    try:
        data = toml.loads(open(filename).read())
        logging.info("Successfully read config file %s", filename)
        return data
    except (FileNotFoundError, toml.TomlDecodeError) as ex:
        print("Error reading configuration file.")
        print(ex)
        print()
        exit(1)


#  Execute the script
if __name__ == "__main__":

    #  Specify settings For the log
    log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'logs', f"AssetCriticalityUpdate.log")
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(levelname)s:  %(asctime)s > %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

    #  Set config file path, and read the configuration.
    conf_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'conf', 'config.toml')
    config_contents = read_config_file(conf_file)

    try:
        AssetCriticalityUpdate(config_contents)

    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected.  Exiting...")
        print()
        print("KeyboardInterrupt detected.  Exiting...")
        print()
        sys.exit(0)


"""
   Copyright 2021 RiskSense, Inc.

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
