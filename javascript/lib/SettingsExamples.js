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
 * Retrieves the value of the FirewallSettingNetworkEngineMode property of a policy.
 * @param {Object} api The Deep Security API modules.
 * @param {String} policyID The ID of the policy.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise that resolves to the property value.
 */
exports.getNetworkEngineMode = function(api, policyID, apiVersion) {
  const policiesApi = new api.PoliciesApi();
  const settingName = "firewallSettingNetworkEngineMode";
  
  return policiesApi.describePolicySetting(policyID, settingName, apiVersion, { overrides: false });
};

/**
 * Sets the value of the FirewallSettingNetworkEngineMode property of a policy to Inline.
 * @param {Object} api The Deep Security API modules.
 * @param {String} policyID The ID of the policy.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise that resolves to the new value of FirewallSettingNetworkEngineMode.
 */
exports.setNetworkEngineModeToInline = function(api, policyID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Setting name and value
    const settingName = "firewallSettingNetworkEngineMode";
    const networkEngineModeValue = new api.SettingValue();
    networkEngineModeValue.value = "Inline";

    // Modify the policy setting on Deep Security Manager
    const policiesApi = new api.PoliciesApi();
    policiesApi
      .modifyPolicySetting(policyID, settingName, networkEngineModeValue, apiVersion, { overrides: false })
      .then(returnedPolicySetting => {
        resolve(returnedPolicySetting.value);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/**
 * Configures Firewall to operate in fail open or fail closed mode for a policy. Demonstrates how to configure multiple policy settings.
 * @param {Object} api The Deep Security API modules.
 * @param {String} policyID The ID of the policy.
 * @param {boolean} failOpen Indicates whether to enable fail open or fail closed mode. Set to true for fail open.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise that resolves to the PolicySettings object of the modified policy.
 */
exports.setFirewallFailOpenBehavior = function(api, policyID, failOpen, apiVersion) {
  return new Promise((resolve, reject) => {
    const modes = {
      failOpen: "Fail open",
      failClosed: "Fail closed"
    };

    // Create the SettingValue objects
    const failureResponseEngineSystem = new api.SettingValue();
    const failureResponsePacketSanityCheck = new api.SettingValue();

    // Set the values
    if (failOpen) {
      failureResponseEngineSystem.value = modes.failOpen;
      failureResponsePacketSanityCheck.value = modes.failOpen;
    } else {
      failureResponseEngineSystem.value = modes.failClosed;
      failureResponsePacketSanityCheck.value = modes.failClosed;
    }

    // Set the value of the setting
    const policySettings = new api.PolicySettings();
    policySettings.firewallSettingFailureResponseEngineSystem = failureResponseEngineSystem;
    policySettings.firewallSettingFailureResponsePacketSanityCheck = failureResponsePacketSanityCheck;

    // Create a policy and add the setting values
    const policy = new api.Policy();
    policy.policySettings = policySettings;

    // Modify the policy on Deep Security Manager.
    const policiesApi = new api.PoliciesApi();
    policiesApi
      .modifyPolicy(policyID, policy, apiVersion, { overrides: false })
      .then(returnedPolicy => {
        resolve(returnedPolicy.policySettings);
      })
      .catch(error => {
        reject(error);
      });
  });
};
