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

import time

def search_policies_by_name(api, configuration, api_version, api_exception, name):
    """ Searches for a policy by name.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param name: The policy name to search for.
    :return: A PoliciesApi object that contains the policies found by the search.
    """

    # Set search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "name"
    search_criteria.string_test = "equal"
    search_criteria.string_value = name

    # Create a search filter
    search_filter = api.SearchFilter(None, [search_criteria])
    search_filter.max_items = 1

    # Perform the search
    try:
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        return policies_api.search_policies(api_version, search_filter=search_filter)

    except api_exception as e:
        return "Exception: " + str(e)


def search_updated_intrusion_prevention_rules(api, configuration, api_version, api_exception, num_days):
    """ Searches for Intrusion Prevention rules that have been updated within a specific number of days.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param num_days: The number of days within which the rules were updated.
    :return: A IntrusionPreventionRulesApi object that contains the rules that were updated within num_days.
    """

    # Time that rules were last updated
    current_time_in_ms = int(round(time.time() * 1000))
    last_updated_in_ms = current_time_in_ms - (num_days * 24 * 60 * 60 * 1000)

    # Set search criteria for the date range
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "lastUpdated"
    search_criteria.first_date_value = last_updated_in_ms
    search_criteria.last_date_value = current_time_in_ms
    search_criteria.first_date_inclusive = True
    search_criteria.last_date_inclusive = True

    # Create a search filter
    search_filter = api.SearchFilter(None, [search_criteria])

    # Perform the search
    try:
        intrusion_prevention_rules_api = api.IntrusionPreventionRulesApi(api.ApiClient(configuration))
        return intrusion_prevention_rules_api.search_intrusion_prevention_rules(api_version, search_filter=search_filter)

    except api_exception as e:
        return "Exception: " + str(e)


def paged_search_computers(api, configuration, api_version, api_exception):
    """ Uses a search filter to create a paged list of computers

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list of computer objects
    """

    # Set search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.id_value = 0
    search_criteria.id_test = "greater-than"

    # Create a search filter with maximum returned items
    page_size = 10
    search_filter = api.SearchFilter()
    search_filter.max_items = page_size
    search_filter.search_criteria = [search_criteria]

    # Perform the search and do work on the results
    computers_api = api.ComputersApi(api.ApiClient(configuration))
    paged_computers = []

    try:
        while True:
            computers = computers_api.search_computers(api_version, search_filter=search_filter)
            num_found = len(computers.computers)
            current_paged_computers = []

            if num_found == 0:
                print("No computers found.")
                break

            for computer in computers.computers:
                current_paged_computers.append(computer)

            paged_computers.append(current_paged_computers)

            # Get the ID of the last computer in the page and return it with the number of computers on the page
            last_id = computers.computers[-1].id
            search_criteria.id_value = last_id
            print("Last ID: " + str(last_id), "Computers found: " + str(num_found))

            if num_found != page_size:
                break

        return paged_computers

    except api_exception as e:
        return "Exception: " + str(e)


def get_computers_with_policy_and_relay_list(api, configuration, api_version, api_exception, relay_list_id, policy_id):
    """ Search for computers that are assigned to a specific policy and relay list.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param relay_list_id: The ID of the relay list.
    :param policy_id: The ID of the policy.
    :return: A ComputersApi object that contains matching computers
    """

    # Set search criteria for platform
    policy_criteria = api.SearchCriteria()
    policy_criteria.field_name = "policyID"
    policy_criteria.numeric_test = "equal"
    policy_criteria.numeric_value = policy_id

    # Set search criteria for relay
    relay_criteria = api.SearchCriteria()
    relay_criteria.field_name = "relayListID"
    relay_criteria.numeric_test = "equal"
    relay_criteria.numeric_value = relay_list_id

    # Create the search filter
    search_filter = api.SearchFilter(None, [policy_criteria, relay_criteria])

    try:
        # Perform the search
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        return computers_api.search_computers(api_version, search_filter=search_filter)

    except api_exception as e:
        return "Exception: " + str(e)

