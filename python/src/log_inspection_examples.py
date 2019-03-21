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
    """ Adds a log inspection rule to a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :param li_rules: A list of log inspection rule IDs to add.
    :return: A PoliciesApi object containing a policy containing the added log inspection rules.
    """

    # Add log inspection rules to the policy from li_rules
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    policy_config_log_inspection = api.LogInspectionPolicyExtension()
    policy_config_log_inspection.rule_ids = li_rules

    # Update the policy with the log inspection rules
    policy = api.Policy()
    policy.log_inspection = policy_config_log_inspection

    try:
        # Modify the policy on Deep Security Manager
        return policies_api.modify_policy(policy_id, policy, api_version)

    except api_exception as e:
        return "Exception: " + str(e)
