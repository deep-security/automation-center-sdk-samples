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

def configure_integrity_monitoring(api, configuration, api_version, api_exception, policy_id, im_rule_ids):
    """ Turns on Integrity Monitoring and adds integrity monitoring rules for a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :param im_rule_ids: A list of integrity monitoring rule IDs.
    :return: The ID of the modified policy.
    """

    # Turn on Integrity Monitoring
    policy_config_integrity_monitoring = api.IntegrityMonitoringPolicyExtension()
    policy_config_integrity_monitoring.state = "on"

    # Add the rule IDs
    policy_config_integrity_monitoring.rule_ids = im_rule_ids

    # Add to a policy
    policy = api.Policy()
    policy.integrity_monitoring = policy_config_integrity_monitoring

    # Modify the policy on Deep Security Manager
    policies_api = api.PoliciesApi(api.ApiClient(configuration))
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
