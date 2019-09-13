# Copyright 2019 Trend Micro.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#



def create_gcp_connector(api, configuration, api_version, api_exception, name, service_account):
    """ Creates a GCP connector.
    :param api              The Deep Security API exports.
    :param configuration    The configuration object to pass to the API client.
    :param api_version      The API version to use.
    :param api_exception    The Deep Security API exception module.
    :param name             The name of the GCP connector.
    :param service_account  The GCP service account used by the GCP connector.
    :return                 The created GCP connector object which contains the created GCP connector ID information.
    """
    
    # Create a GCP connector object
    api_instance = api.GCPConnectorsApi(api.ApiClient(configuration))
    gcp_connector = api.GCPConnector()
    
    # Set the GCP connector properties
    gcp_connector.name = name
    gcp_connector.service_account = service_account
    try:
        # Call create_gcp_connector API to create the GCP connector
        api_response = api_instance.create_gcp_connector(gcp_connector, api_version)
        return api_response
    except api_exception as e:
        print("An exception occurred when calling GCPConnectorsApi.create_google_connector: %s\n" % e)

def submit_gcp_connector_sync_action(api, configuration, api_version, api_exception, gcp_connector_id):
    """ Submits a synchronize action of a GCP connector.
    :param api              The Deep Security API exports.
    :param configuration    The configuration object to pass to the API client.
    :param api_version      The API version to use.
    :param api_exception    The Deep Security API exception module.
    :param gcp_connector_id The GCP connector ID of the target GCP connector.
    :return                 The created Action object which contains the ID and status of the action.
    """
    
    # Create the GCPConnectorActionsApi instance and an Action object to synchronize the GCP connector
    api_instance = api.GCPConnectorActionsApi(api.ApiClient(configuration))
    gcp_connector_action = api.Action()
    gcp_connector_action.type = "synchronize"
    try:
        # Call the create_gcp_connector_action API to create a synchronize action for the target GCP connector
        api_response = api_instance.create_gcp_connector_action(gcp_connector_id, gcp_connector_action, api_version)
        return api_response
    except api_exception as e:
        print("An exception occurred when calling GCPConectorActionsDetailsApi.create_google_connector_action: %s\n" % e)
