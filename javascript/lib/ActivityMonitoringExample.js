/*
 * Copyright 2020 Trend Micro.
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
 * Turns on Activity Monitoring, and set the ActivityEnabled Setting for a policy.
 * @param {Object} api The Deep Security API modules.
 * @param {Number} policyId The ID of the policy to modify.
 * @param {String} apiVersion The version of the api to use.
 * @return {Promise} A promise that contains the ID of the modified policy
 */
exports.configureActivityMonitoring = function(api, policyID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Set the state
    const activityMonitoringPolicyExtension = new api.ActivityMonitoringPolicyExtension();
    activityMonitoringPolicyExtension.state = api.ActivityMonitoringPolicyExtension.StateEnum.on;

    // Add to a policy
    const policy = new api.Policy();
    policy.activityMonitoring = activityMonitoringPolicyExtension;

    // Turn On the ActivityEnabled Setting
    const policySettings = new api.PolicySettings();
    const activityEnabledSetting = new api.SettingValue();
    activityEnabledSetting.value = "On";
    policySettings.activityMonitoringSettingActivityEnabled = activityEnabledSetting;

    // Add the settings
    policy.policySettings = policySettings;

    // Modifies the policy on Deep Security
    const modify = () => {
      const policiesApi = new api.PoliciesApi();
      return policiesApi.modifyPolicy(policyID, policy, apiVersion, { overrides: false });
    };

    modify()
      .then(modifiedPolicy => {
        resolve(modifiedPolicy.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
