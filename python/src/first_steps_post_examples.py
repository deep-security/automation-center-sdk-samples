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

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception

def search_firewall_rules(api, configuration, api_version, api_exception):
    """ Searches the firewall rules for any rule that contains DHCP in the rule name.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list containing all firewall rules that match the search criteria.
    """

    # Define the search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "name"
    search_criteria.string_value = "%DHCP%"
    search_criteria.string_test = "equal"
    search_criteria.string_wildcards = True

    # Create search filter to find the rule
    search_filter = api.SearchFilter(None,[search_criteria])

    # Create a FirewallRulesApi object
    firewall_rules_api = api.FirewallRulesApi(api.ApiClient(configuration))

    try:
        # Perform the search
        firewall_rules = firewall_rules_api.search_firewall_rules(api_version, search_filter=search_filter)
        firewall_rules_list = []
        for rule in firewall_rules.firewall_rules:
            firewall_rules_list.append(rule)
        return firewall_rules

    except api_exception as e:
        return "Exception: " + str(e)

if __name__ == '__main__':
    # Add Deep Security Manager host information to the api client configuration
    configuration = api.Configuration()
    configuration.host = 'https://192.168.17.149:4119/api'

    # Authentication
    configuration.api_key['api-secret-key'] = '2:l069trAePqPRxZUfBqyw442z1DWm9s4u0F/g9bewnFE='

    # Version
    api_version = 'v1'
    print(search_firewall_rules(api, configuration, api_version, api_exception))