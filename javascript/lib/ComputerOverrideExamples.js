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
 * Overrides a computer to enable Firewall reconnaissance scan.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Number} computerID The ID of the computer.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the computer settings object.
 */
exports.overrideReconnaissanceScan = function(api, computerID, apiVersion) {
  // Setting name
  const settingName = "firewallSettingReconnaissanceEnabled";

  // Setting value
  const settingValue = new api.SettingValue();
  settingValue.value = "true";

  let computersApi = new api.ComputersApi();
  return computersApi.modifyComputerSetting(computerID, settingName, settingValue, apiVersion, { overrides: true });
};

/**
 * Obtains a Computer object that contains only overrides.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Object} expand An Expand object that contains a list of computer properties to include in the returned Computer object.
 * @param {Number} computerID The ID of the computer.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the computer ID
 */
exports.getComputerOverrides = function(api, expand, computerID, apiVersion) {
  const computersApi = new api.ComputersApi();
  const opts = {
    overrides: true,
    expand: expand.list()
  };
  return computersApi.describeComputer(computerID, apiVersion, opts);
};
