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

def get_network_engine_mode(api, configuration, api_version, api_exception, policy_id):
    """ Gets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A string with the firewall_setting_network_engine_mode value.
    """

    # Get the policy details from Deep Security Manager
    policies_api = api.PoliciesApi(api.ApiClient(configuration))

    try:
        policy = policies_api.describe_policy(policy_id, api_version, overrides=False)
        policy_settings = policy.policy_settings

        # Get the setting value
        network_engine_mode_value = policy_settings.firewall_setting_network_engine_mode

        return network_engine_mode_value

    except api_exception as e:
        return "Exception: " + str(e)



def set_network_engine_mode_to_inline(api, configuration, api_version, api_exception, policy_id):
    """ Sets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A PoliciesApi object with the modified policy.
    """

    # Create a SettingValue object and set the value to either "Inline" or "Tap"
    network_engine_mode_value = api.SettingValue()
    network_engine_mode_value.value = "Inline"
    policies_api = api.PoliciesApi(api.ApiClient(configuration))

    try:
        # Create a policy and add the setting value
        policy = policies_api.describe_policy(policy_id, api_version)
        policy_settings = policy.policy_settings
        policy_settings.firewall_setting_network_engine_mode = network_engine_mode_value

        # Modify the policy on the Deep Security Manager.
        return policies_api.modify_policy(policy_id, policy, api_version, overrides=False)

    except api_exception as e:
        return "Exception: " + str(e)
