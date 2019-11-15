/*
 * Copyright 2019 Trend Micro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Modifies a policy to set the Container Control state to ON.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} policyID The ID of the policy to modify.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the modified policy.
*/
exports.configureContainerControl = function (api, policyID, apiVersion) {
    return new Promise((resolve, reject) => {
        const policy = new api.Policy();
        const policiesApi = new api.PoliciesApi();
        const containerControlPolicyExtension = new api.ContainerControlPolicyExtension();

        //Turn on container control
        containerControlPolicyExtension.state =
            api.ContainerControlPolicyExtension.StateEnum.on;

        // Configure Action for privileged container
        containerControlPolicyExtension.privilegedContainerAction =
            api.ContainerControlPolicyExtension.PrivilegedContainerActionEnum.detect;

        // Configure Action for unscanned images
        containerControlPolicyExtension.unscannedImagesAction =
            api.ContainerControlPolicyExtension.UnscannedImagesActionEnum.allow;

        // Configure Action for images with malware detected
        containerControlPolicyExtension.malwareDetectedAction =
            api.ContainerControlPolicyExtension.MalwareDetectedActionEnum.block;

        // Adjust the threshold of vulnerabilities and configure action for the images that exceed vulnerability threshold
        const containerControlVulnerabilityThreshold = new api.ContainerControlVulnerabilityThreshold();
        containerControlVulnerabilityThreshold.defcon1Count = 0;
        containerControlVulnerabilityThreshold.criticalCount = 0;
        containerControlVulnerabilityThreshold.highCount = 0;
        containerControlVulnerabilityThreshold.mediumCount = 10;
        containerControlVulnerabilityThreshold.lowCount = -1;
        containerControlVulnerabilityThreshold.negligibleCount = -1;
        containerControlVulnerabilityThreshold.unknownCount = -1;
        containerControlPolicyExtension.vulnerabilityThreshold = containerControlVulnerabilityThreshold;
        containerControlPolicyExtension.vulnerabilityExceedThresholdAction =
            api.ContainerControlPolicyExtension.VulnerabilityExceedThresholdActionEnum.block;

        //Add to the policy
        policy.containerControl = containerControlPolicyExtension;

        //Send the change to Deep Security Manager
        policiesApi.modifyPolicy(policyID, policy, apiVersion, { overrides: false })
            .then(modifiedPolicy => {
                resolve(modifiedPolicy.ID);
            })
            .catch(function(error) {
                reject(error);
            });
    });
};
