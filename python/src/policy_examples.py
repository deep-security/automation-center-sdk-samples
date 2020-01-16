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

def create_policy(api, configuration, api_version, api_exception, policy_name):
    """ Creates a policy that inherits from the base policy

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_name: The name of the policy.
    :return: A PoliciesAPI object for the new policy.
    """

    # Create and configure a new policy
    new_policy = api.Policy()
    new_policy.name = policy_name
    new_policy.description = "Inherits from Base policy"
    new_policy.detection_engine_state = "off"
    new_policy.auto_requires_update = "on"

    # Create search criteria to retrieve the Base Policy
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "name"
    search_criteria.string_test = "equal"
    search_criteria.string_value = "%Base Policy%"
    search_criteria.max_results = 1

    # Create a search filter and pass the search criteria to it
    search_filter = api.SearchFilter(None, [search_criteria])

    # Search for the Base Policy
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    policy_search_results = policies_api.search_policies(api_version, search_filter=search_filter)

    # Set the parent ID of the new policy to the ID of the Base Policy
    new_policy.parent_id = policy_search_results.policies[0].id

    # Add the new policy to Deep Security Manager
    created_policy = policies_api.create_policy(new_policy, api_version)

    return created_policy



def assign_linux_server_policy(api, configuration, api_version, api_exception, computer_id):
    """ Assigns a Linux server policy to a computer.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer to assign the policy to.
    :return: A ComputersApi object that contains the Linux server policy.
    """

    # Create search criteria to retrieve the Base Policy
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "name"
    search_criteria.string_test = "equal"
    search_criteria.string_value = "%Linux Server%"

    # Create a search filter
    search_filter = api.SearchFilter(None, [search_criteria])
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    computers_api = api.ComputersApi(api.ApiClient(configuration))
    computer = api.Computer()

    # Perform the search
    policy_search_results = policies_api.search_policies(api_version, search_filter=search_filter)

    # Assign the policy to the computer
    computer.policy_id = policy_search_results.policies[0].id

    return computers_api.modify_computer(computer_id, computer, api_version)



def selective_reset_for_log_inspection_rule_on_policy(api, configuration, api_version, api_exception, policy_id, rule_id):

    policy_log_inspection_rule_details_api = api.PolicyLogInspectionRuleDetailsApi(api.ApiClient(configuration))

    # Get the rule overrides
    rule_overrides = policy_log_inspection_rule_details_api.describe_log_inspection_rule_on_policy(policy_id, rule_id, api_version, overrides=True)

    # Reset the rule
    policy_log_inspection_rule_details_api.reset_log_inspection_rule_on_policy(policy_id, rule_id, api_version, overrides=False)

    # Add the desired overrides to a new rule
    li_rule_overrides_restored = api.LogInspectionRule()

    if rule_overrides.alert_minimum_severity:
        li_rule_overrides_restored.alert_minimum_severity = rule_overrides.alert_minimum_severity

    if rule_overrides.recommendations_mode:
        li_rule_overrides_restored.recommendations_mode = rule_overrides.recommendations_mode

    # Modify the rule on Deep Security Manager
    return policy_log_inspection_rule_details_api.modify_log_inspection_rule_on_policy(policy_id, rule_id, li_rule_overrides_restored, api_version, overrides=False)
