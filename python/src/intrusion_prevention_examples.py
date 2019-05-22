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


def modify_intrusion_prevention_policy(api, configuration, api_version, api_exception, policy_id, rule_ids):
    """ Turns on the automatic application of recommendation scans for intrusion prevention in a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :param rule_ids: The IDs of the Intrusion Prevention rules to assign.
    :return: The ID of the modified policy.
    """

    # Run in prevent mode
    ip_policy_extension = api.IntrusionPreventionPolicyExtension()
    ip_policy_extension.state = "prevent"

    # Assign rules
    ip_policy_extension.rule_ids = rule_ids

    # Add to a policy
    policy = api.Policy()
    policy.IntrusionPrevention = ip_policy_extension

    # Configure the setting
    policy_settings = api.PolicySettings()
    setting_value = api.SettingValue()
    setting_value.value = "yes"
    policy_settings.intrusion_prevention_setting_auto_apply_recommendations_enables = setting_value

    # Add the setting to a policy
    policy.policy_settings = policy_settings

    try:
        # Modify the policy on Deep Security Manager
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
        return modified_policy.id
    except api_exception as e:
        return "Exception: " + str(e)


def get_assigned_intrusion_prevention_rules(api, configuration, api_version, api_exception):
    """ Retrieves the intrusion prevention rules that are applied to all computers.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A dictionary of objects that contain the computer host name and their assigned rules or None if no rules.
    """

    # Include Intrusion Prevention information in the returned Computer objects
    expand = api.Expand(api.Expand.intrusion_prevention)

    try:
        # Retrieve computers from Deep Security Manager
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        computers_list = computers_api.list_computers(api_version, expand=expand.list(), overrides=False)

        # Extract intrusion prevention rules from the computers
        im_rules = {}
        for computer in computers_list.computers:
            im_rules[computer.host_name] = computer.intrusion_prevention.rule_ids
        return im_rules

    except api_exception as e:
        return "Exception: " + str(e)
