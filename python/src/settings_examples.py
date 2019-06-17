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

    setting_name = "firewall_setting_network_engine_mode"
    policy_settings_class = getattr(api.models, "PolicySettings")
    friendly_setting_name = policy_settings_class.attribute_map[setting_name]

    try:
        # Get the policy details from Deep Security Manager
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        return policies_api.describe_policy_setting(policy_id, friendly_setting_name, api_version, overrides=False)

    except api_exception as e:
        return "Exception: " + str(e)


def set_network_engine_mode_to_inline(api, configuration, api_version, api_exception, policy_id):
    """ Sets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A SettingValue object that contains the modified value.
    """

    # Create a SettingValue object and set the value to either "Inline" or "Tap"
    network_engine_mode_value = api.SettingValue()
    network_engine_mode_value.value = "Inline"

    # Setting name
    #  setting_name = api.SystemSettings.attribute_map[
    #      api.PolicySettings.firewall_setting_network_engine_mode.fget.__name__]
    setting_name = "firewall_setting_network_engine_mode"
    policy_settings_class = getattr(api.models, "PolicySettings")
    friendly_setting_name = policy_settings_class.attribute_map[setting_name]

    try:
        # Modify the setting on Deep Security Manager
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        return policies_api.modify_policy_setting(policy_id, friendly_setting_name, network_engine_mode_value, api_version, overrides=False)

    except api_exception as e:
        return "Exception: " + str(e)


def set_firewall_fail_open_behavior(api, configuration, api_version, api_exception, fail_open, policy_id):
    """ Configures Firewall to operate in fail open or fail closed mode for a policy. Demonstrates how to configure multiple policy settings.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param fail_open: Indicates whether to enable fail open or fail closed mode. Set to True for fail open.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A Policies object with the modified policy.
    """

    # Create the SettingValue objects
    failure_response_engine_system = api.SettingValue()
    failure_response_packet_sanity_check = api.SettingValue()

    # Set the values
    if fail_open:
        failure_response_engine_system.value = failure_response_packet_sanity_check.value = "Fail open"
    else:
        failure_response_engine_system.value = failure_response_packet_sanity_check.value = "Fail closed"

    # Set the setting values and add to a policy
    policy_settings = api.PolicySettings()
    policy_settings.firewall_setting_failure_response_engine_system = failure_response_engine_system
    policy_settings.firewall_setting_failure_response_packet_sanity_check = failure_response_packet_sanity_check

    policy = api.Policy()
    policy.policy_settings = policy_settings

    try:
        # Modify the policy on the Deep Security Manager.
        policies_api = api.PoliciesApi(api.ApiClient(configuration))
        return policies_api.modify_policy(policy_id, policy, api_version, overrides=False)

    except api_exception as e:
        return "Exception: " + str(e)

