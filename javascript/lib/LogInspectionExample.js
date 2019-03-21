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
 * Adds a Log Inspection rule to a policy.
 * @param {Object} api The Deep Security API modules.
 * @param {Number} policyId The ID of the policy to modify.
 * @param {Number} liRules An array of Log Inspection rule IDs to add.
 * @param {String} apiVersion The version of the api to use.
 * @returns {Promise} A promise that contains the modified policy.
 */
exports.configureLogInspection = function(api, policyID, liRules, apiVersion) {
  return new Promise((resolve, reject) => {
    const logInspectionPolicyExtension = new api.LogInspectionPolicyExtension();
    logInspectionPolicyExtension.ruleIDs = liRules;
    //Add to a policy
    const policy = new api.Policy();
    policy.logInspection = logInspectionPolicyExtension;

    //Modifies the policy on Deep Security Manager
    const modify = () => {
      const policiesApi = new api.PoliciesApi();
      return policiesApi.modifyPolicy(policyID, policy, apiVersion, { overrides: false });
    };

    return modify()
      .then(data => {
        resolve(data);
      })
      .catch(error => {
        reject(error);
      });
  });
};
