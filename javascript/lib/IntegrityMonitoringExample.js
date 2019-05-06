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
 * Turns on Integrity Monitoring and adds Integrity Monitoring rules for a policy.
 * @param {Object} api The Deep Security API modules.
 * @param {Number} policyId The ID of the policy to modify.
 * @param {[Number]} imRules An array of integrity monitoring rule IDs.
 * @param {String} apiVersion The version of the api to use.
 * @returns {Promise} A promise that contains the ID of the modified policy
 */
exports.configureIntegrityMonitoring = function(api, policyID, imRules, apiVersion) {
  return new Promise((resolve, reject) => {
    // Turn on Integrity Monitoring
    const integrityMonitoringPolicyExtension = new api.IntegrityMonitoringPolicyExtension();
    integrityMonitoringPolicyExtension.state = api.IntegrityMonitoringPolicyExtension.StateEnum.on;

    // Add rule IDs
    integrityMonitoringPolicyExtension.ruleIDs = imRules;

    // Add to a policy
    const policy = new api.Policy();
    policy.integrityMonitoring = integrityMonitoringPolicyExtension;

    //Modifies the policy on Deep Security Manager
    const modify = () => {
      const policiesApi = new api.PoliciesApi();
      return policiesApi.modifyPolicy(policyID, policy, apiVersion, { overrides: false });
    };

    return modify()
      .then(modifiedPolicy => {
        resolve(modifiedPolicy.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
