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

def configure_container_control(api, configuration, api_version, api_exception, policy_id):
    """ Modifies a policy to set the container control state to on.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :return: A PoliciesApi object that contains the ID of the modified policy.
    """

    # Get the policy
    policies_api = api.PoliciesApi(api.ApiClient(configuration))

    # Turn on Container Control
    container_control_policy_extension = api.ContainerControlPolicyExtension()
    container_control_policy_extension.state = "on"

    # Configure Action for privileged container
    container_control_policy_extension.privileged_container_action = "detect"

    # Configure Action for unscanned images
    container_control_policy_extension.unscanned_images_action = "allow"

    # Configure Action for images with malware detected
    container_control_policy_extension.malware_detected_action = "block"

    # Adjust the threshold of vulnerabilities and configure action for the images that exceed vulnerability threshold
    container_control_vulnerability_threshold = api.ContainerControlVulnerabilityThreshold()
    container_control_vulnerability_threshold.defcon1_count = 0
    container_control_vulnerability_threshold.critical_count = 0
    container_control_vulnerability_threshold.high_count = 0
    container_control_vulnerability_threshold.medium_count = 10
    container_control_vulnerability_threshold.low_count = -1
    container_control_vulnerability_threshold.negligible_count = -1
    container_control_vulnerability_threshold.unknown_count = -1
    container_control_policy_extension.vulnerability_threshold = container_control_vulnerability_threshold
    container_control_policy_extension.vulnerability_exceed_threshold_action = "block"

    # Update the policy
    update_policy = api.Policy()
    update_policy.container_control = container_control_policy_extension

    try:
        # Modify the policy on Deep Security Manager
        container_control_policy = policies_api.modify_policy(policy_id, update_policy, api_version, overrides=False)
        return container_control_policy

    except api_exception as e:
        return "Exception: " + str(e)
