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
    api_instance = api.GCPConnectorsApi(api.ApiClient(configuration))
    gcp_connector = api.GCPConnector()
    gcp_connector.name = name
    gcp_connector.service_account = service_account
    try:
        api_response = api_instance.create_gcp_connector(gcp_connector, api_version)
        return api_response
    except api_exception as e:
        print("An exception occurred when calling GCPConnectorsApi.create_google_connector: %s\n" % e)

def submit_gcp_connector_sync_action(api, configuration, api_version, api_exception, gcp_connector_id):
    api_instance = api.GCPConnectorActionsApi(api.ApiClient(configuration))
    gcp_connector_action = api.Action()
    gcp_connector_action.type = "synchronize"
    try:
        api_response = api_instance.create_gcp_connector_action(gcp_connector_id, gcp_connector_action, api_version)
        return api_response
    except api_exception as e:
        print("An exception occurred when calling GCPConectorActionsDetailsApi.create_google_connector_action: %s\n" % e)
