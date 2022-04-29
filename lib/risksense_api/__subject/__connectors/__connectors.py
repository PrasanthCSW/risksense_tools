""" *******************************************************************************************************************
|
|  Name        : __connectors.py
|  Module      : risksense_api
|  Description : A class to be used for interacting with connectors on the RiskSense Platform.
|  Copyright   : (c) RiskSense, Inc.
|  License     : Apache-2.0 (http://www.apache.org/licenses/LICENSE-2.0)
|
******************************************************************************************************************* """

import json
from ...__subject import Subject
from ..._api_request_handler import *


class Connectors(Subject):

    """ Connectors class """

    class Type:
        """ Connectors.Type class """
        NESSUS = 'NESSUS'
        QUALYS_VULN = 'QUALYS_VULN_FILE_PICKUP'
        QUALYS_VMDR= 'QUALYS_API_VULNERABILITY'
        QUALYS_ASSET = 'QUALYS_ASSET'
        NEXPOSE = 'NEXPOSE_FILE_PICKUP'
        TENEBLE_SEC_CENTER = 'TENEBLE_SECURITY_CENTER'
        BURPSUITE= "BURPSUITE"
        CROWDSTRIKE="FALCONSPOTLIGHT"
        QUALYS_WAS="QUALYS_WAS"
        VERACODE="VERACODE"
        SONAR_CLOUD="SONARCLOUD"
        JIRA = "JIRA"
        SERVICENOW_INCIDENT = "SERVICE_NOW"
        CHECKMARX_OSA = "CHECKMARXOSA"
        CHECKMARX_SAST = "CHECKMARXSAST"
        HCL_APPSCAN = "HCL_ASOC"
        QUALYS_PC="QUALYS_PC"

    class ScheduleFreq:
        """ Connectors.ScheduleFreq class """
        DAILY = "DAILY"
        WEEKLY = "WEEKLY"
        MONTHLY = "MONTHLY"

    def __init__(self, profile):

        """
        Initialization of Connectors object.

        :param profile:     Profile Object
        :type  profile:     _profile

        """

        self.subject_name = "connector"
        Subject.__init__(self, profile, self.subject_name)

    def get_list(self, page_num=0, page_size=150, client_id=None):

        """
        Get a list of connectors associated with the client.

        :param page_num:    The page number of results to be returned.
        :type  page_num:    int

        :param page_size:   The number of results to return per page.
        :type  page_size:   int

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :return:    The JSON response from the platform is returned.
        :rtype:     dict

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "?size=" + str(page_size) + "&page=" + str(page_num)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def create_scanning_connector(self, conn_name, conn_type, conn_url, schedule_freq, network_id,
               username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new scanning connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_type:       The connector type. (Valid options are: Connectors.Type.NESSUS, Connectors.Type.NEXPOSE,Connectors.Type.
                                                                        Connectors.Type.QUALYS_VULN, Connectors.Type.QUALYS_ASSET,Connectors.Type.TENEBLE_SEC_CENTER)
        :type  conn_type:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username_or_access_key:      The username to use for connector authentication.
        :type  username_or_access_key:      str

        :param password_or_secret_key:      The password to use for connector authentication.
        :type  password_or_secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id))

        ssl_cert = kwargs.get('ssl_cert', None)
        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)
        createassetifzerovulnfoundinfile=kwargs.get('create_asset',False)
        reportNamePrefix=kwargs.get('reportnameprefix','')
        authmechanism=kwargs.get('authmechanism','APIKey')
        maxDaystoRetrieve = kwargs.get('maxdaystoretrieve',30)

        if conn_type == Connectors.Type.NESSUS:

            attributes = {
                "accessKey": username_or_access_key,
                "secretKey": password_or_secret_key
            }
        elif conn_type ==Connectors.Type.BURPSUITE:

            attributes ={"username":username_or_access_key,
            "password":password_or_secret_key,"createAssetsIfZeroVulnFoundInFile":createassetifzerovulnfoundinfile}
        
        elif conn_type ==Connectors.Type.SONAR_CLOUD:
            ingestionfindingstype = kwargs.get('ingestionfindingstype',[])
            attributes ={"username":username_or_access_key,
            "password":password_or_secret_key,"createAssetsIfZeroVulnFoundInFile":createassetifzerovulnfoundinfile,"ingestionfindingsType":ingestionfindingstype}

        
        elif conn_type ==Connectors.Type.NEXPOSE or conn_type == Connectors.Type.QUALYS_WAS or conn_type == Connectors.Type.QUALYS_PC:

            attributes ={"username":username_or_access_key,
                "password":password_or_secret_key,
                "reportNamePrefix": reportNamePrefix}
        elif conn_type == Connectors.Type.VERACODE:
            attributes= {"username":username_or_access_key,
                "password":password_or_secret_key,"authMechanism":authmechanism}

        elif conn_type ==Connectors.Type.QUALYS_VULN:

            attributes ={"username":username_or_access_key,
                "password":password_or_secret_key,
                "reportNamePrefix": reportNamePrefix}

        else:
            attributes = {
                "username": username_or_access_key,
                "password": password_or_secret_key
            }

        body = {
            "type": conn_type,
            "name": conn_name,
            "connection": {
                "url": conn_url
            },
            "networkId": network_id,
            "attributes": attributes,
            "autoUrba": auto_urba
        }

        if ssl_cert is not None:
            body['connection'].update(sslCertificates=ssl_cert)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "enabled": True,
                "type": schedule_freq,
                "hourOfDay": hour_of_day
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = 1

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "enabled": True,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "dayOfWeek": day_of_week
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = 1

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "enabled": True,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "dayOfMonth": day_of_month
            }

        else:
            raise ValueError("Schedule freq. should be DAILY, WEEKLY, or MONTHLY.")

        body.update(schedule=connector_schedule)
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        job_id = jsonified_response['id']

        return job_id

    def create_qualyspc(self, conn_name, conn_url, schedule_freq, network_id,
                      username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new qualys pc connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.QUALYS_PC, conn_url, schedule_freq, network_id,
                                       username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id            

    def create_hclappscan(self, conn_name, conn_url, schedule_freq, network_id,
                      username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new hcl appscan connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.HCL_APPSCAN, conn_url, schedule_freq, network_id,
                                       username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id            

    def create_veracode(self, conn_name, conn_url, schedule_freq, network_id,
                      access_key, secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new veracode connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.VERACODE, conn_url, schedule_freq, network_id,
                                       access_key, secret_key, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def create_sonar_cloud(self, conn_name, conn_url, schedule_freq, network_id,
                      access_key, secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new sonar cloud connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.SONAR_CLOUD, conn_url, schedule_freq, network_id,
                                       access_key, secret_key, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def create_nessus(self, conn_name, conn_url, schedule_freq, network_id,
                      access_key, secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Nessus connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.NESSUS, conn_url, schedule_freq, network_id,
                                       access_key, secret_key, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def create_tenableio(self, conn_name, conn_url, schedule_freq, network_id,
                      access_key, secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new tenable io connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.NESSUS, conn_url, schedule_freq, network_id,
                                       access_key, secret_key, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id



    def create_burpsuite(self, conn_name, conn_url, schedule_freq, network_id,
                      username, apikey, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new burpsuite connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.BURPSUITE, conn_url, schedule_freq, network_id,
                                       username,apikey, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id
    
    def create_crowdstrike(self, conn_name, conn_url, schedule_freq, network_id,
                           username, password, auto_urba=True, client_id=None, **kwargs):
        """
        Create a new crowdstrike connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param access_key:      The username to use for connector authentication.
        :type  access_key:      str

        :param secret_key:      The password to use for connector authentication.
        :type  secret_key:      str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

    
        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.CROWDSTRIKE, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def get_jira_project(self, username, password_or_api_token, jira_url, client_id=None):
        """
        Get JIRA Project

        :param username:                    JIRA username
        :type username:                     str

        :param password_or_api_token:       JIRA API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    JIRA Platform URL
        :type jira_url:                     str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :return project_name:               JIRA Project Name
        :rtype project_name:                str

        :return project_key:                JIRA Project Key
        :rtype project_key:                 str

        """
        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/populate"
        connector_populate_body = {
            "type": Connectors.Type.JIRA,
            "username": username,
            "password": password_or_api_token,
            "url": jira_url,
            "projection": "internal"
        }	
        try:
            cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_populate_body)
        except RequestFailed:
            raise            
        print(cred_authorize.text)
        if cred_authorize.status_code == 200:
            cred_authorize_json = json.loads(cred_authorize.text)
            print("[+] These are the available projects in the JIRA platform\n")
            for ind in range(len(cred_authorize_json['projects'])):
                print(f"Index Number - {ind} - {cred_authorize_json['projects'][ind]['displayValue']}")
            print()
            project_index = int(input('Enter the index number of project that you want to select: '))
            project_name = cred_authorize_json['projects'][project_index]['displayValue']
            project_key = cred_authorize_json['projects'][project_index]['value']
        print()
        return project_name, project_key

    def get_jira_issuetype(self, username, password_or_api_token, jira_url, project_key, client_id=None):
        """
        Get JIRA Issue Type

        :param username:                    JIRA username
        :type username:                     str

        :param password_or_api_token:       JIRA API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    JIRA Platform URL
        :type jira_url:                     str

        :param project_key:                 JIRA Project Key
        :type project_key:                  str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :return issue_type_name:            JIRA Issue Type Name
        :rtype issue_type_name:             str

        :return issue_type_key:             JIRA Issue Type Key
        :rtype issue_type_key:              str

        """
        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/populate/project/{project_key}/issueType"

        connector_populate_body = {
            "type": Connectors.Type.JIRA,
            "username": username,
            "password": password_or_api_token,
            "url": jira_url,
            "projection": "internal"
        }
        try:
            issue_type = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_populate_body)
        except RequestFailed:
            raise            

        if issue_type.status_code == 200:
            issue_type_json = json.loads(issue_type.text)
            print("[+] These are the available issue type for this project\n")
            for ind in range(len(issue_type_json['issueTypes'])):
                print(f"Index Number - {ind} - {issue_type_json['issueTypes'][ind]['displayValue']}")
            print()
            issue_type_index = int(input('Enter the index number of issue type that you want to select: '))
            issue_type_name = issue_type_json['issueTypes'][issue_type_index]['displayValue']
            issue_type_key = issue_type_json['issueTypes'][issue_type_index]['value']
        print()
        return issue_type_name, issue_type_key

    def get_jira_tagtype_ticketstatus(self, username, password_or_api_token, jira_url, project_key, issue_type_key, client_id=None):
        """
        Get JIRA Tag Type and Ticket Status options

        :param username:                    JIRA username
        :type username:                     str

        :param password_or_api_token:       JIRA API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    JIRA Platform URL
        :type jira_url:                     str

        :param project_key:                 JIRA Project Key
        :type project_key:                  str

        :param issue_type_key:              JIRA Issue Type Key
        :type issue_type_key:               str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :return tag_type_name:              JIRA Issue Type Name
        :rtype tag_type_name:               str

        :return closed_status_value:        JIRA Closed status name
        :rtype closed_status_value:         str

        :return closed_status_key:          JIRA Closed status Key
        :rtype closed_status_key:           str

        :return ticket_sync_string:         JIRA Ticket sync string
        :rtype ticket_sync_string:          str

        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/populate/project/{project_key}/issueType/{issue_type_key}"

        connector_populate_body = {
            "type": Connectors.Type.JIRA,
            "username": username,
            "password": password_or_api_token,
            "url": jira_url,
            "projection": "internal"
        }	

        try:
            connector_fill = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_populate_body)
        except RequestFailed:
            raise            

        if connector_fill.status_code == 200:
            connector_fill_json = json.loads(connector_fill.text)
            print("[+] These are the available tag type in the RS platform\n")
            for ind in range(len(connector_fill_json['tagTypeDefaultOptions'])):
                print(f"Index Number - {ind} - {connector_fill_json['tagTypeDefaultOptions'][ind]['displayValue']}")
            print()
            tag_type_index = int(input('Enter the index number of tag type that you want to select: '))
            tag_type_name = connector_fill_json['tagTypeDefaultOptions'][tag_type_index]['displayValue']
            print()
            print("[+] These are the available ticket status options for this project\n")
            ticket_sync_status = []
            for ind in range(len(connector_fill_json['connectorSettings']['statusOptions'])):
                ticket_sync_status.append(connector_fill_json['connectorSettings']['statusOptions'][ind]['displayValue'])
                print(f"Index Number - {ind} - {connector_fill_json['connectorSettings']['statusOptions'][ind]['displayValue']}")
            print()
            closed_status_index = int(input('Enter the index number of ticket closed status that you want to select: '))
            closed_status_value = connector_fill_json['connectorSettings']['statusOptions'][ind]['displayValue']
            closed_status_key = connector_fill_json['connectorSettings']['statusOptions'][ind]['value']
            ticket_sync_status.remove(closed_status_value)
            ticket_sync_string = ",".join(ticket_sync_status)
        print()
        return tag_type_name, closed_status_value, closed_status_key, ticket_sync_string

    def create_jira_connector(self, jira_connector_name, username, password_or_api_token, jira_url, project_name, project_key, issue_type_name, issue_type_key, tag_type_name, closed_status_key, closed_status_value, ticket_sync_string, client_id=None):
        """
        Create a JIRA Connector

        :param jira_connector_name:         JIRA Connector Name
        :type jira_connector_name:          str

        :param username:                    JIRA username
        :type username:                     str

        :param password_or_api_token:       JIRA API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    JIRA Platform URL
        :type jira_url:                     str

        :param project_name:                JIRA Project Name
        :type project_name:                 str

        :param project_key:                 JIRA Project Key
        :type project_key:                  str

        :param issue_type_name:             JIRA Issue Type Name
        :type issue_type_name:              str

        :param issue_type_key:              JIRA Issue Type Key
        :type issue_type_key:               str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :param tag_type_name:               JIRA Issue Type Name
        :type tag_type_name:                str

        :param closed_status_value:         JIRA Closed status name
        :type closed_status_value:          str

        :param closed_status_key:           JIRA Closed status Key
        :type closed_status_key:            str

        :param ticket_sync_string:          JIRA Ticket sync string
        :type ticket_sync_string:           str

        :return connector_id:               Created JIRA connector ID
        :rtype connector_id:                int

        """
        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id))

        connector_creation_body = {
                "name": jira_connector_name,
                "type": Connectors.Type.JIRA,
                "schedule": {
                    "enabled": True,
                    "type": "DAILY",
                    "hourOfDay": 0
                },
                "attributes": {
                    "username": username,
                    "password": password_or_api_token
                },
                "connection": {
                    "url": jira_url
                },
                "connectorField": {
                    "type": Connectors.Type.JIRA,
                    "project": {
                        "displayValue": project_name,
                        "value": project_key
                    },
                    "issueType": {
                        "displayValue": issue_type_name,
                        "value": issue_type_key
                    },
                    "descriptionFields": [
                        {
                            "key": "owner",
                            "enabled": False
                        },
                        {
                            "key": "name",
                            "enabled": False
                        },
                        {
                            "key": "description",
                            "enabled": False
                        },
                        {
                            "key": "priority",
                            "enabled": False
                        },
                        {
                            "key": "start_date",
                            "enabled": False
                        },
                        {
                            "key": "due_date",
                            "enabled": False
                        },
                        {
                            "key": "percentage_complete",
                            "enabled": False
                        },
                        {
                            "key": "days_remaining",
                            "enabled": False
                        },
                        {
                            "key": "open_findings",
                            "enabled": False
                        },
                        {
                            "key": "total_findings",
                            "enabled": False
                        },
                        {
                            "key": "host_findings",
                            "enabled": False
                        },
                        {
                            "key": "app_findings",
                            "enabled": False
                        },
                        {
                            "key": "assigned_users",
                            "enabled": False
                        },
                        {
                            "key": "data_refresh",
                            "enabled": False
                        },
                        {
                            "key": "assigned",
                            "enabled": False
                        },
                        {
                            "key": "unassigned",
                            "enabled": False
                        },
                        {
                            "key": "accepted",
                            "enabled": False
                        },
                        {
                            "key": "false_positive",
                            "enabled": False
                        }
                    ],
                    "dynamicFields": [
                        {
                            "key": "priority",
                            "value": "10000",
                            "displayValue": "NoPrio"
                        },
                        {
                            "key": "summary",
                            "value": "",
                            "displayValue": ""
                        }
                    ],
                    "tagSyncField": "",
                    "slaDateField": "",
                    "tagTypeDefaultValue": tag_type_name,
                    "usePluginInfoFields": [
                        "summary",
                        "description"
                    ],
                    "lockedFields": [],
                    "connectorSettings": {
                        "initialState": "",
                        "enabledTagRemoval": False,
                        "closeFindingsOnTicketCloseEnabled": False,
                        "closeTicketOnFindingsCloseEnabled": True,
                        "closedStateKey": closed_status_key,
                        "closedStateLabel": closed_status_value,
                        "enabledUploadAttachment": True,
                        "closeStatusesOfTicketToUpdate": ticket_sync_string
                    }
                }
            }
        try:
            connector_create = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_creation_body)
        except RequestFailed:
            raise

        if connector_create.status_code == 201:
            connector_create_json = json.loads(connector_create.text)
            connector_id = connector_create_json['id']

        return connector_id

    def get_snow_fields(self, snow_username, snow_password_or_token, snow_url, client_id=None):
        """
        Get Service Now Incident type connector Fields

        :param username:                    Service Now username
        :type username:                     str

        :param password_or_api_token:       Service Now API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    Service Now Platform URL
        :type jira_url:                     str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :return tag_type_name:              Service Now Issue Type Name
        :rtype tag_type_name:               str

        :return closed_status_value:        Service Now Closed status name
        :rtype closed_status_value:         str

        :return closed_status_key:          Service Now Closed status Key
        :rtype closed_status_key:           str

        :return ticket_sync_string:         Service Now Ticket sync string
        :rtype ticket_sync_string:          str

        """      

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/populate"

        connector_populate_body = {
            "type": Connectors.Type.SERVICENOW_INCIDENT,
            "username": snow_username,
            "password": snow_password_or_token,
            "url": snow_url,
            "projection": "internal"
        }		

        try:
            cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_populate_body)
        except RequestFailed:
            raise    

        if cred_authorize.status_code == 200:
            cred_authorize_json = json.loads(cred_authorize.text)
            print("[+] These are the available tag type in the RS platform\n")
            for ind in range(len(cred_authorize_json['tagTypeFieldOptions'])):
                print(f"Index Number - {ind} - {cred_authorize_json['tagTypeFieldOptions'][ind]['displayValue']}")
            print()				
            tag_type_index = int(input('Enter the index number of tag type that you want to select: '))
            tag_type_name = cred_authorize_json['tagTypeFieldOptions'][tag_type_index]['displayValue']
            print()
            print("[+] These are the available ticket status options for this project\n")
            ticket_sync_status = []
            for ind in range(len(cred_authorize_json['connectorSettings']['statusOptions'])):
                ticket_sync_status.append(cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue'])
                print(f"Index Number - {ind} - {cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue']}")
            print()
            closed_status_index = int(input('Enter the index number of ticket closed status that you want to select: '))
            closed_status_value = cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue']
            closed_status_key = cred_authorize_json['connectorSettings']['statusOptions'][ind]['value']
            ticket_sync_status.remove(closed_status_value)
            ticket_sync_string = ",".join(ticket_sync_status)	
        print()

        return tag_type_name, closed_status_value, closed_status_key, ticket_sync_string

    def get_snow_fields(self, snow_username, snow_password_or_token, snow_url, client_id=None):
        """
        Get Service Now Incident type connector Fields

        :param username:                    Service Now username
        :type username:                     str

        :param password_or_api_token:       Service Now API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    Service Now Platform URL
        :type jira_url:                     str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :return tag_type_name:              Service Now Issue Type Name
        :rtype tag_type_name:               str

        :return closed_status_value:        Service Now Closed status name
        :rtype closed_status_value:         str

        :return closed_status_key:          Service Now Closed status Key
        :rtype closed_status_key:           str

        :return ticket_sync_string:         Service Now Ticket sync string
        :rtype ticket_sync_string:          str

        """      

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/populate"

        connector_populate_body = {
            "type": Connectors.Type.SERVICENOW_INCIDENT,
            "username": snow_username,
            "password": snow_password_or_token,
            "url": snow_url,
            "projection": "internal"
        }		

        try:
            cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_populate_body)
        except RequestFailed:
            raise    

        if cred_authorize.status_code == 200:
            cred_authorize_json = json.loads(cred_authorize.text)
            print("[+] These are the available tag type in the RS platform\n")
            for ind in range(len(cred_authorize_json['tagTypeFieldOptions'])):
                print(f"Index Number - {ind} - {cred_authorize_json['tagTypeFieldOptions'][ind]['displayValue']}")
            print()				
            tag_type_index = int(input('Enter the index number of tag type that you want to select: '))
            tag_type_name = cred_authorize_json['tagTypeFieldOptions'][tag_type_index]['displayValue']
            print()
            print("[+] These are the available ticket status options for this project\n")
            ticket_sync_status = []
            for ind in range(len(cred_authorize_json['connectorSettings']['statusOptions'])):
                ticket_sync_status.append(cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue'])
                print(f"Index Number - {ind} - {cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue']}")
            print()
            closed_status_index = int(input('Enter the index number of ticket closed status that you want to select: '))
            closed_status_value = cred_authorize_json['connectorSettings']['statusOptions'][ind]['displayValue']
            closed_status_key = cred_authorize_json['connectorSettings']['statusOptions'][ind]['value']
            ticket_sync_status.remove(closed_status_value)
            ticket_sync_string = ",".join(ticket_sync_status)	
        print()

        return tag_type_name, closed_status_value, closed_status_key, ticket_sync_string

    def create_snow_connector(self, snow_connector_name, snow_username, snow_password_or_token, snow_url, tag_type_name, closed_status_value, closed_status_key, ticket_sync_string, client_id=None):
        """
        Create a Service Now Incident type Connector

        :param snow_connector_name:         JIRA Connector Name
        :type snow_connector_name:          str

        :param snow_username:                    JIRA username
        :type snow_username:                     str

        :param snow_password_or_api_token:       JIRA API Token/Password
        :type snow_password_or_api_token:        str

        :param snow_url:                    JIRA Platform URL
        :type snow_url:                     str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :param tag_type_name:               JIRA Issue Type Name
        :type tag_type_name:                str

        :param closed_status_value:         JIRA Closed status name
        :type closed_status_value:          str

        :param closed_status_key:           JIRA Closed status Key
        :type closed_status_key:            str

        :param ticket_sync_string:          JIRA Ticket sync string
        :type ticket_sync_string:           str

        :return connector_id:               Created JIRA connector ID
        :rtype connector_id:                int

        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id))    

        connector_creation_body = {
            "name": snow_connector_name,
            "type": Connectors.Type.SERVICENOW_INCIDENT,
            "schedule": {
                "enabled": True,
                "type": "DAILY",
                "hourOfDay": 0
            },
            "attributes": {
                "username":snow_username,
                "password": snow_password_or_token
            },
            "connection": {
                "url": snow_url
            },
            "connectorField": {
                "type": Connectors.Type.SERVICENOW_INCIDENT,
                "defaultTemplateId": "",
                "templates": [],
                "descriptionFields": [
                    {
                        "key": "accepted",
                        "enabled": False
                    },
                    {
                        "key": "app_findings",
                        "enabled": False
                    },
                    {
                        "key": "assigned",
                        "enabled": False
                    },
                    {
                        "key": "assigned_users",
                        "enabled": False
                    },
                    {
                        "key": "data_refresh",
                        "enabled": False
                    },
                    {
                        "key": "days_remaining",
                        "enabled": False
                    },
                    {
                        "key": "description",
                        "enabled": False
                    },
                    {
                        "key": "due_date",
                        "enabled": False
                    },
                    {
                        "key": "false_positive",
                        "enabled": False
                    },
                    {
                        "key": "host_findings",
                        "enabled": False
                    },
                    {
                        "key": "name",
                        "enabled": False
                    },
                    {
                        "key": "open_findings",
                        "enabled": False
                    },
                    {
                        "key": "owner",
                        "enabled": False
                    },
                    {
                        "key": "percentage_complete",
                        "enabled": False
                    },
                    {
                        "key": "priority",
                        "enabled": False
                    },
                    {
                        "key": "start_date",
                        "enabled": False
                    },
                    {
                        "key": "total_findings",
                        "enabled": False
                    },
                    {
                        "key": "unassigned",
                        "enabled": False
                    }
                ],
                "selectedOptionalFields": [
                    "priority",
                    "description",
                    "short_description",
                    "assignment_group",
                    "urgency",
                    "due_date"
                ],
                "defaultSupportedFieldValues": [
                    {
                        "key": "priority",
                        "value": "3",
                        "displayValue": "3 - Moderate"
                    },
                    {
                        "key": "urgency",
                        "value": "2",
                        "displayValue": "2 - Medium"
                    }
                ],
                "tagSyncField": "",
                "slaDateField": "due_date",
                "tagTypeDefaultValue": tag_type_name,
                "connectorSettings": {
                    "initialState": "",
                    "enabledTagRemoval": False,
                    "closeFindingsOnTicketCloseEnabled": False,
                    "closeTicketOnFindingsCloseEnabled": True,
                    "closedStateKey": closed_status_key,
                    "closedStateLabel": closed_status_value,
                    "enabledUploadAttachment": True,
                    "closeStatusesOfTicketToUpdate":ticket_sync_string
                },
                "usePluginInfoFields": [
                    "description",
                    "short_description"
                ]
            }
        }

        try:
            connector_create = self.request_handler.make_request(ApiRequestHandler.POST, url, body=connector_creation_body)
        except RequestFailed:
            raise

        if connector_create.status_code == 201:
            connector_create_json = json.loads(connector_create.text)
            connector_id = connector_create_json['id']

        return connector_id

    def create_checkmarx_osa_connector(self, conn_name, conn_url, username, password, conn_status, schedule_freq, network_id, auto_urba=True, client_id=None, **kwargs):
        """
        Create a new Checkmarx OSA scanning connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :type  conn_type:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run, Type : Str, Available values : 1-7
        :keyword day_of_month:  The day of the month the connector should run, Type : Str, Available values : 1-31
        :keyword createAssetsIfZeroVulnFoundInFile: Create assets if zero vulnerability found in file. Type : Bool, Available values : True or False
        :keyword maxDaysToRetrieve: Max days to retrieve scan data. Type : Integer, Available values : 30,60,90,180,365

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0] 

        ssl_cert = kwargs.get('ssl_cert', None)
        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)
        createAssetsIfZeroVulnFoundInFile = kwargs.get('createAssetsIfZeroVulnFoundInFile', None)
        maxDaysToRetrieve = kwargs.get('maxDaysToRetrieve', None)

        project_selection = input("Select \"ALL\" projects in checkmarx? Please enter 'y' if YES or enter 'n' if NO: ")
        if project_selection == 'n':
            print("\n[+] As you selected No, these are the list of projects available in checkmarx:\n")
            populate_url = self.api_base_url.format(str(client_id)) + "/populate"
            connector_populate_body = {
                "type": Connectors.Type.CHECKMARX_OSA,
                "username": username,
                "password": password,
                "url": conn_url,
                "projection": "internal"
            }	
            try:
                cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, populate_url, body=connector_populate_body)
            except RequestFailed:
                raise            

            if cred_authorize.status_code == 200:
                cred_authorize_json = json.loads(cred_authorize.text) 
                for ind in range(len(cred_authorize_json['projectList'])):
                    print(f"Index Number - {ind} - {cred_authorize_json['projectList'][ind]['displayValue']}")
                print()
                project_indexes_list = list(map(int, input("Enter the index numbers of projects that you want to select. Enter index numbers as comma separated values if multiple projects need to be selected: ").split(",")))
                project_selected_list = []
                for value in project_indexes_list:
                    project_selected_list.append(cred_authorize_json['projectList'][value]['value'])
                project_selected_string = ",".join(project_selected_list)
                print(project_selected_string)
        elif project_selection == 'y':
            project_selected_string = "ALL"

        connector_create_url = self.api_base_url.format(str(client_id))

        if maxDaysToRetrieve is None:
            max_days = 30

        connector_create_body = {
            "type": Connectors.Type.CHECKMARX_OSA,
            "name": conn_name,
            "networkId": network_id,
            "connection": {
                "url": conn_url
            },
            "schedule": {
            },
            "attributes": {
                "username": username,
                "password": password,
                "maxDaysToRetrieve": max_days,
                "enableFortifyToPullFPRIntegratedFile": True,
                "checkmarxChosenProjectListToPull": project_selected_string,
                "findingTypeTobePulled": [
                    "vulnerabilities",
                    "licenses"
                ]
            },
            "autoUrba": auto_urba
        }

        if ssl_cert is not None:
            connector_create_body['connection'].update(sslCertificates=ssl_cert)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": day_of_week,
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": day_of_month,
                "cronSchdule":None
            }

        else:
            raise ValueError("Schedule freq. should be DAILY, WEEKLY, or MONTHLY.")

        connector_create_body.update(schedule=connector_schedule)

        if createAssetsIfZeroVulnFoundInFile is None:
            create_asset = True
        
        connector_create_body['attributes'].update(createAssetsIfZeroVulnFoundInFile=create_asset)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, connector_create_url, body=connector_create_body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        job_id = jsonified_response['id']

        return job_id        

    def create_checkmarx_sast_connector(self, conn_name, conn_url, username, password, conn_status, schedule_freq, network_id, auto_urba=True, client_id=None, **kwargs):
        """
        Create a new Checkmarx SAST scanning connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :type  conn_type:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run, Type : Str, Available values : 1-7
        :keyword day_of_month:  The day of the month the connector should run, Type : Str, Available values : 1-31
        :keyword createAssetsIfZeroVulnFoundInFile: Create assets if zero vulnerability found in file. Type : Bool, Available values : True or False
        :keyword generateShortDescription: Generate Short Description. Type : Bool, Available values : True or False

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0] 

        ssl_cert = kwargs.get('ssl_cert', None)
        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)
        createAssetsIfZeroVulnFoundInFile = kwargs.get('createAssetsIfZeroVulnFoundInFile', None)
        generateShortDescription = kwargs.get('generateShortDescription', None)        

        project_selection = input("Select \"ALL\" projects in checkmarx? Please enter 'y' if YES or enter 'n' if NO: ")
        if project_selection == 'n':
            print("\n[+] As you selected No, these are the list of projects available in checkmarx:\n")
            populate_url = self.api_base_url.format(str(client_id)) + "/populate"
            connector_populate_body = {
                "type": Connectors.Type.CHECKMARX_OSA,
                "username": username,
                "password": password,
                "url": conn_url,
                "projection": "internal"
            }	
            try:
                cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, populate_url, body=connector_populate_body)
            except RequestFailed:
                raise            

            if cred_authorize.status_code == 200:
                cred_authorize_json = json.loads(cred_authorize.text) 
                for ind in range(len(cred_authorize_json['projectList'])):
                    print(f"Index Number - {ind} - {cred_authorize_json['projectList'][ind]['displayValue']}")
                print()
                project_indexes_list = list(map(int, input("Enter the index numbers of projects that you want to select. Enter index numbers as comma separated values if multiple projects need to be selected: ").split(",")))
                project_selected_list = []
                for value in project_indexes_list:
                    project_selected_list.append(cred_authorize_json['projectList'][value]['value'])
                project_selected_string = ",".join(project_selected_list)
                print(project_selected_string)
        elif project_selection == 'y':
            project_selected_string = "ALL"

        connector_create_url = self.api_base_url.format(str(client_id))

        if generateShortDescription is None:
            generate_short_description = True

        connector_create_body = {
            "type": Connectors.Type.CHECKMARX_SAST,
            "name": conn_name,
            "networkId": network_id,
            "attributes": {
                "username": username,
                "password": password,
                "checkmarxChosenProjectListToPull": project_selected_string,
                "generateShortDescription": generate_short_description
            },
            "connection": {
                "url": conn_url
            },
            "schedule": {
            },
            "autoUrba": auto_urba
        }

        if ssl_cert is not None:
            connector_create_body['connection'].update(sslCertificates=ssl_cert)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": day_of_week,
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": day_of_month,
                "cronSchdule":None
            }

        else:
            raise ValueError("Schedule freq. should be DAILY, WEEKLY, or MONTHLY.")

        connector_create_body.update(schedule=connector_schedule)

        if createAssetsIfZeroVulnFoundInFile is None:
            create_asset = True
        
        connector_create_body['attributes'].update(createAssetsIfZeroVulnFoundInFile=create_asset)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, connector_create_url, body=connector_create_body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        job_id = jsonified_response['id']

        return job_id        



    def create_qualys_was(self, conn_name, conn_url, schedule_freq, network_id,
                           username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Qualys Web application connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.QUALYS_WAS, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id


    def create_qualys_vuln(self, conn_name, conn_url, schedule_freq, network_id,
                           username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Qualys Vulnerability connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.QUALYS_VULN, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id


    def create_qualys_asset(self, conn_name, conn_url, schedule_freq, network_id,
                            username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Qualys Asset connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.QUALYS_ASSET, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def create_qualys_vmdr(self, conn_name, conn_url, schedule_freq, network_id,
                       username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new qualys vm connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.QUALYS_VMDR, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id


    def create_nexpose(self, conn_name, conn_url, schedule_freq, network_id,
                       username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Nexpose connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.NEXPOSE, conn_url, schedule_freq, network_id,
                                       username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id

    def create_teneble(self, conn_name, conn_url, schedule_freq, network_id,
                       username, password, auto_urba=True, client_id=None, **kwargs):

        """
        Create a new Teneble Security Center connector.

        :param conn_name:       The connector name.
        :type  conn_name:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            connector_id = self.create_scanning_connector(conn_name, Connectors.Type.TENEBLE_SEC_CENTER, conn_url, schedule_freq,
                                       network_id, username, password, auto_urba, client_id, **kwargs)
        except (RequestFailed, ValueError):
            raise

        return connector_id



    def get_connector_detail(self, connector_id, client_id=None):

        """
        Get the details associated with a specific connector.

        :param connector_id:    The connector ID.
        :type  connector_id:    int

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :return:    The JSON response from the platform is returned.
        :rtype:     dict

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/{}".format(str(connector_id))

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def update(self, connector_id, conn_type, conn_name, conn_url, network_id, schedule_freq,
               username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_type:               Type of Connector (Valid options are: Connectors.Type.NESSUS,
                                                                              Connectors.Type.NEXPOSE,
                                                                              Connectors.Type.QUALYS_VULN,
                                                                              Connectors.Type.QUALYS_ASSET,
                                                                              Connectors.Type.TENEBLE_SEC_CENTER)
        :type  conn_type:               str

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:   Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:   bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        connector_schedule = None

        url = self.api_base_url.format(str(client_id)) + "/{}".format(str(connector_id))

        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "type": schedule_freq,
                "hourOfDay": hour_of_day
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = 1

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "dayOfWeek": day_of_week
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = 1

            if hour_of_day is None:
                hour_of_day = 12

            connector_schedule = {
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "dayOfMonth": day_of_month
            }

        if conn_type == Connectors.Type.NESSUS:
            attributes = {
                "accessKey": username_or_access_key,
                "secretKey": password_or_secret_key
            }

        else:
            attributes = {
                "username": username_or_access_key,
                "password": password_or_secret_key
            }

        body = {
            "type": conn_type,
            "name": conn_name,
            "connection": {
                "url": conn_url
            },
            "schedule": connector_schedule,
            "networkId": network_id,
            "attributes": attributes,
            "autoUrba": auto_urba
        }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        returned_id = jsonified_response['id']

        return returned_id
    


    def update_nessus_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing Nessus connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:   Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:   bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.NESSUS, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_sonarcloud(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing Sonarcloud connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.SONAR_CLOUD, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_veracode(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing Veracode connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.VERACODE, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_tenableio(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing Tenable io connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.NESSUS, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_hclappscan(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing hclappscan connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.HCL_APPSCAN, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_qualys_vm_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing QUALYS VULN connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.QUALYS_VMDR, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_qualys_pc_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing QUALYS PC connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.QUALYS_PC, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_jira_connector(self, connector_id, jira_connector_name, username, password_or_api_token, jira_url, project_name, project_key, issue_type_name, issue_type_key, tag_type_name, closed_status_key, closed_status_value, ticket_sync_string, client_id=None):
        """
        Updates a JIRA Connector
        :param connector_id:                The Connector Id
        :type connector_id:                 str

        :param jira_connector_name:         JIRA Connector Name
        :type jira_connector_name:          str

        :param username:                    JIRA username
        :type username:                     str

        :param password_or_api_token:       JIRA API Token/Password
        :type password_or_api_token:        str

        :param jira_url:                    JIRA Platform URL
        :type jira_url:                     str

        :param project_name:                JIRA Project Name
        :type project_name:                 str

        :param project_key:                 JIRA Project Key
        :type project_key:                  str

        :param issue_type_name:             JIRA Issue Type Name
        :type issue_type_name:              str

        :param issue_type_key:              JIRA Issue Type Key
        :type issue_type_key:               str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :param tag_type_name:               JIRA Issue Type Name
        :type tag_type_name:                str

        :param closed_status_value:         JIRA Closed status name
        :type closed_status_value:          str

        :param closed_status_key:           JIRA Closed status Key
        :type closed_status_key:            str

        :param ticket_sync_string:          JIRA Ticket sync string
        :type ticket_sync_string:           str

        :return connector_id:               Created JIRA connector ID
        :rtype connector_id:                int

        """        
        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/{}".format(str(connector_id))

        connector_creation_body = {
                "name": jira_connector_name,
                "type": Connectors.Type.JIRA,
                "schedule": {
                    "enabled": True,
                    "type": "DAILY",
                    "hourOfDay": 0
                },
                "attributes": {
                    "username": username,
                    "password": password_or_api_token
                },
                "connection": {
                    "url": jira_url
                },
                "id": connector_id,
                "connectorField": {
                    "type": Connectors.Type.JIRA,
                    "project": {
                        "displayValue": project_name,
                        "value": project_key
                    },
                    "issueType": {
                        "displayValue": issue_type_name,
                        "value": issue_type_key
                    },
                    "descriptionFields": [
                        {
                            "key": "owner",
                            "enabled": False
                        },
                        {
                            "key": "name",
                            "enabled": False
                        },
                        {
                            "key": "description",
                            "enabled": False
                        },
                        {
                            "key": "priority",
                            "enabled": False
                        },
                        {
                            "key": "start_date",
                            "enabled": False
                        },
                        {
                            "key": "due_date",
                            "enabled": False
                        },
                        {
                            "key": "percentage_complete",
                            "enabled": False
                        },
                        {
                            "key": "days_remaining",
                            "enabled": False
                        },
                        {
                            "key": "open_findings",
                            "enabled": False
                        },
                        {
                            "key": "total_findings",
                            "enabled": False
                        },
                        {
                            "key": "host_findings",
                            "enabled": False
                        },
                        {
                            "key": "app_findings",
                            "enabled": False
                        },
                        {
                            "key": "assigned_users",
                            "enabled": False
                        },
                        {
                            "key": "data_refresh",
                            "enabled": False
                        },
                        {
                            "key": "assigned",
                            "enabled": False
                        },
                        {
                            "key": "unassigned",
                            "enabled": False
                        },
                        {
                            "key": "accepted",
                            "enabled": False
                        },
                        {
                            "key": "false_positive",
                            "enabled": False
                        }
                    ],
                    "dynamicFields": [
                        {
                            "key": "priority",
                            "value": "10000",
                            "displayValue": "NoPrio"
                        },
                        {
                            "key": "summary",
                            "value": "",
                            "displayValue": ""
                        }
                    ],
                    "tagSyncField": "",
                    "slaDateField": "",
                    "tagTypeDefaultValue": tag_type_name,
                    "usePluginInfoFields": [
                        "summary",
                        "description"
                    ],
                    "lockedFields": [],
                    "connectorSettings": {
                        "initialState": "",
                        "enabledTagRemoval": False,
                        "closeFindingsOnTicketCloseEnabled": False,
                        "closeTicketOnFindingsCloseEnabled": True,
                        "closedStateKey": closed_status_key,
                        "closedStateLabel": closed_status_value,
                        "enabledUploadAttachment": True,
                        "closeStatusesOfTicketToUpdate": ticket_sync_string
                    }
                }
            }
        try:
            connector_create = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=connector_creation_body)
        except RequestFailed:
            raise

        if connector_create.status_code == 200:
            connector_create_json = json.loads(connector_create.text)
            connector_id = connector_create_json['id']

        return connector_id

    def update_snow_connector(self, connector_id, snow_connector_name, snow_username, snow_password_or_token, snow_url, tag_type_name, closed_status_value, closed_status_key, ticket_sync_string, client_id=None):
        """
        Update a Service Now Incident type Connector

        :param connector_id:                The Connector Id
        :type connector_id:                 int

        :param snow_connector_name:         JIRA Connector Name
        :type snow_connector_name:          str

        :param snow_username:                    JIRA username
        :type snow_username:                     str

        :param snow_password_or_api_token:       JIRA API Token/Password
        :type snow_password_or_api_token:        str

        :param snow_url:                    JIRA Platform URL
        :type snow_url:                     str

        :param client_id:                   RS Client ID
        :type client_id:                    int

        :param tag_type_name:               JIRA Issue Type Name
        :type tag_type_name:                str

        :param closed_status_value:         JIRA Closed status name
        :type closed_status_value:          str

        :param closed_status_key:           JIRA Closed status Key
        :type closed_status_key:            str

        :param ticket_sync_string:          JIRA Ticket sync string
        :type ticket_sync_string:           str

        :return connector_id:               Created JIRA connector ID
        :rtype connector_id:                int

        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/{connector_id}"  

        connector_creation_body = {
            "name": snow_connector_name,
            "type": Connectors.Type.SERVICENOW_INCIDENT,
            "schedule": {
                "enabled": True,
                "type": "DAILY",
                "hourOfDay": 0
            },
            "attributes": {
                "username":snow_username,
                "password": snow_password_or_token
            },
            "connection": {
                "url": snow_url
            },
            "id": connector_id,
            "connectorField": {
                "type": Connectors.Type.SERVICENOW_INCIDENT,
                "defaultTemplateId": "",
                "templates": [],
                "descriptionFields": [
                    {
                        "key": "accepted",
                        "enabled": False
                    },
                    {
                        "key": "app_findings",
                        "enabled": False
                    },
                    {
                        "key": "assigned",
                        "enabled": False
                    },
                    {
                        "key": "assigned_users",
                        "enabled": False
                    },
                    {
                        "key": "data_refresh",
                        "enabled": False
                    },
                    {
                        "key": "days_remaining",
                        "enabled": False
                    },
                    {
                        "key": "description",
                        "enabled": False
                    },
                    {
                        "key": "due_date",
                        "enabled": False
                    },
                    {
                        "key": "false_positive",
                        "enabled": False
                    },
                    {
                        "key": "host_findings",
                        "enabled": False
                    },
                    {
                        "key": "name",
                        "enabled": False
                    },
                    {
                        "key": "open_findings",
                        "enabled": False
                    },
                    {
                        "key": "owner",
                        "enabled": False
                    },
                    {
                        "key": "percentage_complete",
                        "enabled": False
                    },
                    {
                        "key": "priority",
                        "enabled": False
                    },
                    {
                        "key": "start_date",
                        "enabled": False
                    },
                    {
                        "key": "total_findings",
                        "enabled": False
                    },
                    {
                        "key": "unassigned",
                        "enabled": False
                    }
                ],
                "selectedOptionalFields": [
                    "priority",
                    "description",
                    "short_description",
                    "assignment_group",
                    "urgency",
                    "due_date"
                ],
                "defaultSupportedFieldValues": [
                    {
                        "key": "priority",
                        "value": "3",
                        "displayValue": "3 - Moderate"
                    },
                    {
                        "key": "urgency",
                        "value": "2",
                        "displayValue": "2 - Medium"
                    }
                ],
                "tagSyncField": "",
                "slaDateField": "due_date",
                "tagTypeDefaultValue": tag_type_name,
                "connectorSettings": {
                    "initialState": "",
                    "enabledTagRemoval": False,
                    "closeFindingsOnTicketCloseEnabled": False,
                    "closeTicketOnFindingsCloseEnabled": True,
                    "closedStateKey": closed_status_key,
                    "closedStateLabel": closed_status_value,
                    "enabledUploadAttachment": True,
                    "closeStatusesOfTicketToUpdate":ticket_sync_string
                },
                "usePluginInfoFields": [
                    "description",
                    "short_description"
                ]
            }
        }

        try:
            connector_create = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=connector_creation_body)
        except RequestFailed:
            raise

        if connector_create.status_code == 200:
            connector_create_json = json.loads(connector_create.text)
            connector_id = connector_create_json['id']

        return connector_id

    def update_checkmarx_osa_connector(self, conn_name, connector_id, conn_url, username, password, conn_status, schedule_freq, network_id, auto_urba=True, client_id=None, **kwargs): 
        """
        Update a new Checkmarx OSA scanning connector.

        :param conn_name:       The connector name.
        :type conn_name:        str

        :param connector_id:    The connector ID.
        :type  connector_id:    int

        :type  conn_type:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run, Type : Str, Available values : 1-7
        :keyword day_of_month:  The day of the month the connector should run, Type : Str, Available values : 1-31
        :keyword createAssetsIfZeroVulnFoundInFile: Create assets if zero vulnerability found in file. Type : Bool, Available values : True or False
        :keyword maxDaysToRetrieve: Max days to retrieve scan data. Type : Integer, Available values : 30,60,90,180,365

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0] 

        ssl_cert = kwargs.get('ssl_cert', None)
        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)
        createAssetsIfZeroVulnFoundInFile = kwargs.get('createAssetsIfZeroVulnFoundInFile', None)
        maxDaysToRetrieve = kwargs.get('maxDaysToRetrieve', None)

        project_selection = input("Select \"ALL\" projects in checkmarx? Please enter 'y' if YES or enter 'n' if NO: ")
        if project_selection == 'n':
            print("\n[+] As you selected No, these are the list of projects available in checkmarx:\n")
            populate_url = self.api_base_url.format(str(client_id)) + "/populate"
            connector_populate_body = {
                "type": Connectors.Type.CHECKMARX_OSA,
                "username": username,
                "password": password,
                "url": conn_url,
                "projection": "internal"
            }	
            try:
                cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, populate_url, body=connector_populate_body)
            except RequestFailed:
                raise            

            if cred_authorize.status_code == 200:
                cred_authorize_json = json.loads(cred_authorize.text) 
                for ind in range(len(cred_authorize_json['projectList'])):
                    print(f"Index Number - {ind} - {cred_authorize_json['projectList'][ind]['displayValue']}")
                print()
                project_indexes_list = list(map(int, input("Enter the index numbers of projects that you want to select. Enter index numbers as comma separated values if multiple projects need to be selected: ").split(",")))
                project_selected_list = []
                for value in project_indexes_list:
                    project_selected_list.append(cred_authorize_json['projectList'][value]['value'])
                project_selected_string = ",".join(project_selected_list)
                print(project_selected_string)
        elif project_selection == 'y':
            project_selected_string = "ALL"

        connector_create_url = self.api_base_url.format(str(client_id)) + f"/{str(connector_id)}"

        if maxDaysToRetrieve is None:
            max_days = 30

        connector_create_body = {
            "type": Connectors.Type.CHECKMARX_OSA,
            "name": conn_name,
            "networkId": network_id,
            "connection": {
                "url": conn_url
            },
            "schedule": {
            },
            "attributes": {
                "username": username,
                "password": password,
                "maxDaysToRetrieve": max_days,
                "enableFortifyToPullFPRIntegratedFile": True,
                "checkmarxChosenProjectListToPull": project_selected_string,
                "findingTypeTobePulled": [
                    "vulnerabilities",
                    "licenses"
                ]
            },
            "id": connector_id,
            "autoUrba": auto_urba
        }

        if ssl_cert is not None:
            connector_create_body['connection'].update(sslCertificates=ssl_cert)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": day_of_week,
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": day_of_month,
                "cronSchdule":None
            }

        else:
            raise ValueError("Schedule freq. should be DAILY, WEEKLY, or MONTHLY.")

        connector_create_body.update(schedule=connector_schedule)

        if createAssetsIfZeroVulnFoundInFile is None:
            create_asset = True
        
        connector_create_body['attributes'].update(createAssetsIfZeroVulnFoundInFile=create_asset)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, connector_create_url, body=connector_create_body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        job_id = jsonified_response['id']

        return job_id  

    def update_checkmarx_sast_connector(self, conn_name, connector_id, conn_url, username, password, conn_status, schedule_freq, network_id, auto_urba=True, client_id=None, **kwargs): 
        """
        Update a new Checkmarx SAST scanning connector.

        :param conn_name:       The connector name.
        :type conn_name:        str

        :param connector_id:    The connector ID.
        :type  connector_id:    int

        :type  conn_type:       str

        :param conn_url:        The URL for the connector to communicate with.
        :type  conn_url:        str

        :param username:        The username to use for connector authentication.
        :type  username:        str

        :param password:        The password to use for connector authentication.
        :type  password:        str

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param network_id:      The network ID
        :type  network_id:      int

        :param auto_urba:       Automatically run URBA after connector runs?
        :type  auto_urba:       bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword ssl_cert:      Optional SSL certificate.
        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run, Type : Str, Available values : 1-7
        :keyword day_of_month:  The day of the month the connector should run, Type : Str, Available values : 1-31
        :keyword createAssetsIfZeroVulnFoundInFile: Create assets if zero vulnerability found in file. Type : Bool, Available values : True or False
        :keyword maxDaysToRetrieve: Max days to retrieve scan data. Type : Integer, Available values : 30,60,90,180,365

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0] 

        ssl_cert = kwargs.get('ssl_cert', None)
        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)
        createAssetsIfZeroVulnFoundInFile = kwargs.get('createAssetsIfZeroVulnFoundInFile', None)
        generateShortDescription = kwargs.get('generateShortDescription', None)        

        project_selection = input("Select \"ALL\" projects in checkmarx? Please enter 'y' if YES or enter 'n' if NO: ")
        if project_selection == 'n':
            print("\n[+] As you selected No, these are the list of projects available in checkmarx:\n")
            populate_url = self.api_base_url.format(str(client_id)) + "/populate"
            connector_populate_body = {
                "type": Connectors.Type.CHECKMARX_OSA,
                "username": username,
                "password": password,
                "url": conn_url,
                "projection": "internal"
            }	
            try:
                cred_authorize = self.request_handler.make_request(ApiRequestHandler.POST, populate_url, body=connector_populate_body)
            except RequestFailed:
                raise            

            if cred_authorize.status_code == 200:
                cred_authorize_json = json.loads(cred_authorize.text) 
                for ind in range(len(cred_authorize_json['projectList'])):
                    print(f"Index Number - {ind} - {cred_authorize_json['projectList'][ind]['displayValue']}")
                print()
                project_indexes_list = list(map(int, input("Enter the index numbers of projects that you want to select. Enter index numbers as comma separated values if multiple projects need to be selected: ").split(",")))
                project_selected_list = []
                for value in project_indexes_list:
                    project_selected_list.append(cred_authorize_json['projectList'][value]['value'])
                project_selected_string = ",".join(project_selected_list)
                print(project_selected_string)
        elif project_selection == 'y':
            project_selected_string = "ALL"

        connector_create_url = self.api_base_url.format(str(client_id)) + f"/{str(connector_id)}"

        if generateShortDescription is None:
            generate_short_description = True

        connector_create_body = {
            "type": Connectors.Type.CHECKMARX_SAST,
            "name": conn_name,
            "networkId": network_id,
            "attributes": {
                "username": username,
                "password": password,
                "checkmarxChosenProjectListToPull": project_selected_string,
                "generateShortDescription": generate_short_description
            },
            "connection": {
                "url": conn_url
            },
            "schedule": {
            },
            "id": connector_id,
            "autoUrba": auto_urba
        }

        if ssl_cert is not None:
            connector_create_body['connection'].update(sslCertificates=ssl_cert)

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None:
                day_of_week = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": day_of_week,
                "daysOfMonth": "1",
                "cronSchdule":None
            }

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None:
                day_of_month = "1"

            if hour_of_day is None:
                hour_of_day = 0

            connector_schedule = {
                "enabled": conn_status,
                "type": schedule_freq,
                "hourOfDay": hour_of_day,
                "daysOfWeek": "1",
                "daysOfMonth": day_of_month,
                "cronSchdule":None
            }

        else:
            raise ValueError("Schedule freq. should be DAILY, WEEKLY, or MONTHLY.")

        connector_create_body.update(schedule=connector_schedule)

        if createAssetsIfZeroVulnFoundInFile is None:
            create_asset = True
        
        connector_create_body['attributes'].update(createAssetsIfZeroVulnFoundInFile=create_asset)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, connector_create_url, body=connector_create_body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        job_id = jsonified_response['id']

        return job_id        

    def update_qualys_was_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing QUALYS VULN connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.QUALYS_WAS, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_qualys_vuln_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                     username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing QUALYS VULN connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.QUALYS_VULN, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_qualys_asset_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing QUALYS ASSET connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.QUALYS_ASSET, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_nexpose_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                 username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing NEXPOSE connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:   Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:   bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.NEXPOSE, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def update_teneble_connector(self, connector_id, conn_name, conn_url, network_id, schedule_freq,
                                 username_or_access_key, password_or_secret_key, auto_urba=True, client_id=None, **kwargs):

        """
        Update an existing TENEBLE SECURITY CENTER connector

        :param connector_id:            Connector ID to update
        :type  connector_id:            int

        :param conn_name:               The name for the connector
        :type  conn_name:               str

        :param conn_url:                The URL for the connector to communicate with.
        :type  conn_url:                str

        :param network_id:              The network ID
        :type  network_id:              int

        :param schedule_freq:           The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                                Connectors.ScheduleFreq.WEEKLY,
                                                                                Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:           str

        :param username_or_access_key:  The username or access key to be used
        :type  username_or_access_key:  str

        :param password_or_secret_key:  The password or secret key to be used
        :type  password_or_secret_key:  str

        :param auto_urba:               Indicates whether URBA should be automatically run after connector runs.
        :type  auto_urba:               bool

        :param client_id:               Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:               int

        :keyword hour_of_day:   The time the connector should run. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        try:
            returned_id = self.update(connector_id, Connectors.Type.TENEBLE_SEC_CENTER, conn_name, conn_url, network_id, schedule_freq,
                                      username_or_access_key, password_or_secret_key, auto_urba, client_id, **kwargs)
        except RequestFailed:
            raise

        return returned_id

    def delete(self, connector_id, delete_tag=True, client_id=None):

        """
        Delete a connector.

        :param connector_id:    The connector ID.
        :type  connector_id:    int

        :param delete_tag:      Force delete tag associated with connector?
        :type  delete_tag:      bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :return:    Indicator reflecting whether or not the operation was successful.
        :rtype:     bool

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/{}".format(str(connector_id))

        body = {
            "deleteTag": delete_tag
        }

        try:
            self.request_handler.make_request(ApiRequestHandler.DELETE, url, body)
        except RequestFailed:
            raise

        success = True

        return success

    def get_jobs(self, connector_id, page_num=0, page_size=150, client_id=None):

        """
        Get the jobs associated with a connector.

        :param connector_id:    The connector ID.
        :type  connector_id:    int

        :param page_num:        The page number of results to be returned.
        :type  page_num:        int

        :param page_size:       The number of results to return per page.
        :type page_size:        int

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :return:    The JSON response from the platform is returned.
        :rtype:     dict

        :raises RequestFailed:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/{}/job".format(str(connector_id))

        params = {'page': page_num, 'size': page_size}

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url, params=params)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def update_schedule(self, connector_id, schedule_freq, enabled, client_id=None, **kwargs):

        """
        Update the schedule of an existing Connector.

        :param connector_id:    Connector ID
        :type  connector_id:    int

        :param schedule_freq:   The frequency for the connector to run. Connectors.ScheduleFreq.DAILY,
                                                                        Connectors.ScheduleFreq.WEEKLY,
                                                                        Connectors.ScheduleFreq.MONTHLY
        :type  schedule_freq:   str

        :param enabled:         Enable connector?
        :type  enabled:         bool

        :param client_id:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  client_id:       int

        :keyword hour_of_day:   The time the connector should run. Req. for DAILY, WEEKLY, and MONTHLY. Integer. 0-23.
        :keyword day_of_week:   The day of the week the connector should run.  Req. for WEEKLY. Integer. 1-7
        :keyword day_of_month:  The day of the month the connector should run. Req. for MONTHLY. Integer. 1-31

        :return:    The connector ID from the platform is returned.
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        hour_of_day = kwargs.get('hour_of_day', None)
        day_of_week = kwargs.get('day_of_week', None)
        day_of_month = kwargs.get('day_of_month', None)

        url = self.api_base_url.format(str(client_id)) + "/{}/schedule".format(str(connector_id))

        body = {
            "type": schedule_freq,
            "enabled": enabled
        }

        if schedule_freq == Connectors.ScheduleFreq.DAILY:

            if hour_of_day is None:
                raise ValueError("hour_of_day is required for a DAILY connector schedule.")

            body.update(hourOfDay=hour_of_day)

        elif schedule_freq == Connectors.ScheduleFreq.WEEKLY:

            if day_of_week is None and hour_of_day is None:
                raise ValueError("hour_of_day and day_of_week are required for a WEEKLY connector schedule.")

            if day_of_week is None:
                raise ValueError("day_of_week is required for a WEEKLY connector schedule.")

            if hour_of_day is None:
                raise ValueError("hour_of_day is required for a WEEKLY connector schedule.")

            body.update(hourOfDay=hour_of_day)
            body.update(dayOfWeek=day_of_week)

        elif schedule_freq == Connectors.ScheduleFreq.MONTHLY:

            if day_of_month is None and hour_of_day is None:
                raise ValueError("day_of_month and day_of_week are required for a WEEKLY connector schedule.")

            if day_of_month is None:
                raise ValueError("day_of_month is required for a WEEKLY connector schedule.")

            if hour_of_day is None:
                raise ValueError("hour_of_day is required for a WEEKLY connector schedule.")

            body.update(hourOfDay=hour_of_day)
            body.update(dayOfMonth=day_of_month)

        else:
            raise ValueError("schedule_freq should be one of DAILY, WEEKLY, or MONTHLY")

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        returned_id = jsonified_response['id']

        return returned_id

    # Future: Add support for ticket connectors (SNOW, JIRA, etc.).


"""
   Copyright 2022 RiskSense, Inc.
   
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
