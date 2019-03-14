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

def modify_firewall_policy(api, configuration, api_version, api_exception, policy_id):
    """ Modifies a policy to set the firewall state to on and disables reconnaissance scan.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :return: A PoliciesApi object that contains the ID of the modified policy.
    """
    #
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    policy = api.Policy()
    firewall_policy_extension = api.FirewallPolicyExtension()

    # Turn on firewall
    firewall_policy_extension.state = "on"

    # Add the firewall state to the policy
    policy.firewall = firewall_policy_extension

    # Turn off reconnaissance scan
    policy_settings = api.PolicySettings()
    setting_value = api.SettingValue()
    setting_value.value = False
    policy_settings.firewall_setting_reconnaissance_enabled = setting_value

    # Add reconnaissance scan state to the policy
    policy.policy_settings = policy_settings

    try:
        # Modify the policy on Deep Security Manager
        policies = policies_api.modify_policy(policy_id, policy, api_version)
        return policies

    except api_exception as e:
        return "Exception: " + str(e)
