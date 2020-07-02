# Copyright 2020 Trend Micro.
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


def configure_activity_monitoring(api, configuration, api_version, api_exception, policy_id):
    """ Turns on activity_monitoring, and set the ActivityEnabled Setting for a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :return: The ID of the modified policy.
    """

    # Enable Activity Monitoring
    policy_config_activity_monitoring = api.ActivityMonitoringPolicyExtension()
    policy_config_activity_monitoring.state = "on"

    # Add to a policy
    policy = api.Policy()
    policy.activity_monitoring = policy_config_activity_monitoring

    # Turn On the ActivityEnabled Setting
    policy_settings = api.PolicySettings()
    activity_enabled_setting = api.SettingValue()
    activity_enabled_setting.value = "On"
    policy_settings.activity_monitoring_setting_activity_enabled = activity_enabled_setting

    # Add the settings
    policy.policy_settings = policy_settings

    # Modify the policy on Deep Security Manager
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    return modified_policy.id
