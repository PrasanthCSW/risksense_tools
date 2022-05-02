""" *******************************************************************************************************************
|
|  Name        :  __notifications.py
|  Module      :  risksense_api
|  Description :  A class to be used for interacting with RiskSense platform notifications.
|  Copyright   :  (c) RiskSense, Inc.
|  License     :  Apache-2.0
|
******************************************************************************************************************* """

import json
from tkinter import N
from .. import Subject
from ..._params import *
from ..._api_request_handler import *


class Notifications(Subject):

    """ Notifications class """

    def __init__(self, profile):

        """
        Initialization of Notifications object.

        :param profile:     Profile Object
        :type  profile:     _profile

        """

        self.subject_name = "rsNotifications"
        Subject.__init__(self, profile, self.subject_name)
    
    def subscribe_notifications(self,notificationtypeid,subscribe,client_id=None):

        """
        Subscribe to a notification

        :param notificationtypeid:  The notification id to subscribe.
        :type  notificationtypeid:  int

        :param subscribe:  Whether to subscribe or not
        :type  subscribe:  Bool

        :param client_id:  The client id , if none will provide the default client id
        :type  client_id:  int

        :return:    Success json
        :rtype:     json

        :raises RequestFailed:
        :raises ValueError:
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/subscribe"
        print(url)
        
        body = {"notificationTypeId":notificationtypeid,                     "subscribe":subscribe}
        print(body)
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise
        print(raw_response)
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response


    def listrules(self, client_id):

        """
        In development
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id))+"/rules"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        
        return jsonified_response

    def updatenotifications(self, rules,client_id=None):

        """
        In development
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/rules"

        body = {
            "rules": rules
        }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response)

        return jsonified_response


    def markasread(self,notificationids,markasread,client_id=None):

        """
        Mark as read/unread notifications

        :param notificationtypeid:  The notification id to subscribe.
        :type  notificationtypeid:  int

        :param markasread:  Whether to markread or not
        :type  subscribe:   Bool

        :param client_id:  The client id , if none will provide the default client id
        :type  client_id:  int

        :return:    Success json
        :rtype:     json
        
        """

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/mark-as-read"
        
        body = {
                "notificationIds": notificationids,
                "markAsRead": markasread
                }

        try:
            raw_response=self.request_handler.make_request(ApiRequestHandler.PUT, url,body=body)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response)

        return jsonified_response   

    def create_delivery_channel(self, channelname, channeltype, webhookcontenttype,
                               addressDetails,verificationcode,client_id=None):

        """
        Creates delivery channel for user based on the type of channel

        :param channelname:       The name of the channel .
        :type  channelname:       str
        
        :param channeltype:       The type of the delivery channel either email or other delivery types .
        :type  channeltype:       str
        
        :param webhookcontentype: The type of webhook content .
        :type  webhookcontentype: null
        
        :param addressdetails:    The address to where notifcations appear .
        :type  addressdetails:    str
        
        :param verificationcode:  The verification code which will be send to your address .
        :type  verificationcode:  int
        
        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int"""

        if client_id is None:
            client_id = self._use_default_client_id()[0]
        addressDetails=[{
            "address":addressDetails,"verification_code":verificationcode
        }]

        url = self.api_base_url.format(str(client_id)) + "/channel"

        body = {
                "channelName": channelname,
                "channelType": channeltype,
                "webhookContentType": webhookcontenttype,
                "addressDetails": addressDetails
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def edit_delivery_channel(self,channelid, channelname, channeltype, webhookcontenttype,
                               addressDetails,disabled,shared,client_id=None):

        """In development"""
        """
        Edit delivery channel for user based on the type of channel

        :param channelname:       The name of the channel .
        :type  channelname:       str
        
        :param channeltype:       The type of the delivery channel either email or other delivery types .
        :type  channeltype:       str
        
        :param webhookcontentype: The type of webhook content .
        :type  webhookcontentype: null
        
        :param addressdetails:    The address to where notifcations appear .
        :type  addressdetails:    str
        
        :param disabled:  choose enable or disable based on true or false.
        :type  disabled:  bool
        
        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int"""

        if client_id is None:
            client_id = self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/channel"

        body = {
                "id": channelid,
                "channelName": channelname,
                "channelType": channeltype,
                "webhookContentType": webhookcontenttype,
                "disabled": disabled,
                "shared": shared,
                "addressDetails": addressDetails
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def delete_delivery_channel(self,channelids,client_id=None):

        """
        Delete delivery channel for user

        :param channelids:       The channel ids to delete.
        :type  channelids:       int
        
        :param channeltype:      The client id , if client is none , takes default client id .
        :type  channeltype:      int        


        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/channel"

        body ={
                "channelIds": channelids
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.DELETE, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
    
    def list_channel(self,order,client_id=None):

        
        """
        Lists all delivery channels in  client

        :param order:       The order either asc or desc on how the channels will populate.
        :type  order:       str
        
        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        


        """
        
        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/admin/channel/{order}"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def send_verification_code(self,channelname,channeladdress,channeltype,client_id=None):
        
        """
        Sends verification code to the user

        :param channelname:       The name of the channel .
        :type  channelname:       str
        
        :param channeltype:       The type of the delivery channel either email or other delivery types .
        :type  channeltype:       str
       
        :param channel address:    The address to where verification code needs to be sent .
        :type  channel address:    str
        
        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        


        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/sendverificationcode"

        body={
                "channelName": channelname,
                "channelDetails": [
                    {
                    "channelAddress": channeladdress,
                    "channelType": channeltype
                    }
                ]
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def get_model(self, client_id=None):

        """
        Lists all projection models for notifications in  client
        
        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/model"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def search_filters(self, client_id=None):

        """
        Lists all filters for notifications in  client
        
        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/filter"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def notification_search(self,filters,client_id=None):
 
        """
        Lists all notifications based on filters for client

        :param filters:     The filters which needs to be applied to fetch notifications
        :type  filters:     list
        
        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/search"
        body={
                "filters": filters,
                "projection": "basic",
                "sort": [
                    {
                    "field": "id",
                    "direction": "ASC"
                    }
                ],
                "page": 0,
                "size": 20
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def search_fields(self,client_id=None):

        """
        Lists all quickfilters for rs notifications for client

        :param client_id:   The client id , if client is none , takes default client id .
        :type  client_id:   int        

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/quick-filters/count"
        body={
                "subject": "rsNotifications",
                "filterRequest": {
                    "filters": [
                    {
                        "field": "subject",
                        "exclusive": False,
                        "operator": "IN",
                        "value": "groups"
                    }
                    ]
                }
                }
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        return jsonified_response
    
    def enablenotification(self,id,channelname,channeltype,client_id=None):

        """
        Enables the delivery channel for notifications

        :param id:       The id of the delivery channel .
        :type  id:       str
        
        :param channelname:       The name of the channel .
        :type  channelname:       str
        
        :param channeltype:       The type of the delivery channel either email or other delivery types .
        :type  channeltype:       str

        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int   

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/admin/channel"
        body= {"id":id,"channelName":channelname,"channelType":channeltype,"disabled":False}
        print(body)

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
    
    def disablenotification(self,id,channelname,channeltype,client_id=None):

        """
        Disables the delivery channel for notifications

        :param id:       The id of the delivery channel .
        :type  id:       str
        
        :param channelname:       The name of the channel .
        :type  channelname:       str
        
        :param channeltype:       The type of the delivery channel either email or other delivery types .
        :type  channeltype:       str

        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int   

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + "/admin/channel"
        body= {"id":id,"channelName":channelname,"channelType":channeltype,"disabled":True}

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
   
    def get_notifications(self,client_id=None):

        """
        Gets all notifications for the client

        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int   

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]
        
        url = self.api_base_url.format(str(client_id)) + "/page?page=0&size=50&order=desc"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        return jsonified_response

    
    def list_channel_admin(self,order,client_id=None):
        """
        In testing
        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/channel/admin/{order}"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
  
    def get_notification(self,notification_id,client_id=None):

        """
        Gets specific notification for the client

        :param client id:         The notification id whose information is fetched .
        :type  client id:         int   

        :param client id:         The client id, if none, will select default client id .
        :type  client id:         int   

        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/detail?notification_id={notification_id}"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def get_delivery_channel_template(self,client_id=None):
        """
        In testing
        """

        if client_id is None:
            client_id= self._use_default_client_id()[0]

        url = self.api_base_url.format(str(client_id)) + f"/delivery-channel-template"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    
    

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
