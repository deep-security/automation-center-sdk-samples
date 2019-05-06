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

def configure_log_inspection(api, configuration, api_version, api_exception, policy_id, li_rules):
    """ Turns on Log Inspection and adds a Log Inspection rule for a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :param li_rules: A list of log inspection rule IDs to add.
    :return: The ID of the modified policy.
    """

    # Set the state
    policy_config_log_inspection = api.LogInspectionPolicyExtension()
    policy_config_log_inspection.state = "on"

    # Add the rules
    policy_config_log_inspection.rule_ids = li_rules

    # Add to a policy
    policy = api.Policy()
    policy.log_inspection = policy_config_log_inspection

    try:
        # Modify the policy on Deep Security Manager
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
        return modified_policy.id

    except api_exception as e:
        return "Exception: " + str(e)
