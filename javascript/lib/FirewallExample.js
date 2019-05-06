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

/**
 * Modifies a policy to set the firewall state to ON, assign rules, and enable reconnassaince scan.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Array.<Number>} ruleIDs The IDs of the Firewall rules to assign.
 * @param {String} policyID The ID of the policy to modify.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the modified policy.
 */
exports.modifyFirewallPolicy = function(api, ruleIDs, policyID, apiVersion) {
  return new Promise((resolve, reject) => {
    const policy = new api.Policy();
    const policiesApi = new api.PoliciesApi();
    const firewallPolicyExtension = new api.FirewallPolicyExtension();

    // Turn on firewall
    firewallPolicyExtension.state = api.FirewallPolicyExtension.StateEnum.on;

    // Assign rules
    firewallPolicyExtension.ruleIDs = ruleIDs;

    // Add to the policy
    policy.firewall = firewallPolicyExtension;

    // Turn on reconnaisance scan
    const policySettings = new api.PolicySettings();
    const settingValue = new api.SettingValue();
    settingValue.value = "true";
    policySettings.firewallSettingReconnaissanceEnabled = settingValue;

    // Add to the policy
    policy.policySettings = policySettings;

    // Send the change to Deep Security Manager
    policiesApi
      .modifyPolicy(policyID, policy, apiVersion, { overrides: false })
      .then(modifiedPolicy => {
        resolve(modifiedPolicy.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
