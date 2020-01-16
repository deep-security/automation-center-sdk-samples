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

def configure_web_reputation(api, configuration, api_version, api_exception, policy_id, security_level):
    """ Turns on web reputation, sets the security level, and uses Smart Protection for a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :param security_level: The security level to set for Web Reputation.
    :return: The ID of the modified policy.
    """

    # Enable Web Reputation
    policy_config_web_reputation = api.WebReputationPolicyExtension()
    policy_config_web_reputation.state = "on"

    # Add to a policy
    policy = api.Policy()
    policy.web_reputation = policy_config_web_reputation

    # Set the security level
    policy_settings = api.PolicySettings()
    security_level_setting = api.SettingValue()
    security_level_setting.value = security_level
    policy_settings.web_reputation_setting_security_level = security_level_setting

    # Enable Smart Protection
    smart_protection_allow_global = api.SettingValue()
    smart_protection_allow_global.value = True
    policy_settings.web_reputation_setting_smart_protection_local_server_allow_off_domain_global = smart_protection_allow_global

    # Add the settings
    policy.policy_settings = policy_settings

    # Modify the policy on Deep Security Manager
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    return modified_policy.id
