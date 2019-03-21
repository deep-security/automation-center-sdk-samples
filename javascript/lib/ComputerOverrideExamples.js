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
 * Overrides a computer to enable Firewall reconnaissance scan.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Number} computerID The ID of the computer.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the computer settings object.
 */
exports.overrideReconnaissanceScan = function(api, computerID, apiVersion) {
  return new Promise((resolve, reject) => {
    const settingValue = new api.SettingValue();
    settingValue.value = "false";

    let computerSettings = new api.ComputerSettings();
    computerSettings.firewallSettingReconnaissanceEnabled = settingValue;

    let computer = new api.Computer();
    computer.computerSettings = computerSettings;

    let computersApi = new api.ComputersApi();
    computersApi
      .modifyComputer(computerID, computer, apiVersion, { overrides: true })
      .then(modifiedComputer => {
        resolve(modifiedComputer.computerSettings);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Obtains a Computer object that contains only overrides.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Number} computerID The ID of the computer.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the computer object.
 */
exports.getComputerOverrides = function(api, computerID, apiVersion) {
  return new Promise((resolve, reject) => {
    const computersApi = new api.ComputersApi();
    computersApi
      .describeComputer(computerID, apiVersion, { overrides: true })
      .then(computer => {
        resolve(computer);
      })
      .catch(error => {
        reject(error);
      });
  });
};
