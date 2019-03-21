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
 * Configures the maximum number of active sessions.
 * Demonstrates how to configure system properties.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @returs {Promise} The promise that SystemSettingsApi.modifySystemSettings returns.
 */
exports.configureSystemSettings = function(api, apiVersion) {
  // Create the settings value
  const maxSessions = new api.SettingValue();
  maxSessions.value = "20";

  // Create a SystemSettings object and set the setting value
  const systemSettings = new api.SystemSettings();
  systemSettings.platformSettingActiveSessionsMax = maxSessions;

  // Modify the settings on Deep Security Manager
  const systemSettingsApi = new api.SystemSettingsApi();
  return systemSettingsApi.modifySystemSettings(systemSettings, apiVersion);
};

/*
 * Creates a computer on Deep Security Manager.
 * @param {String} hostname The hostname or IP address that resolves to the computer.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @returs {Promise} A promise that contains the ID of the computer.
 */
exports.addComputer = function(hostname, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create a Computer object and set the hostname
    const computer = new api.Computer();
    computer.hostName = hostname;

    // Create the computer on Deep Security Manager and resolve the ID
    const computersApi = new api.ComputersApi();
    computersApi
      .createComputer(computer, apiVersion, { overrides: false })
      .then(returnedComputer => {
        resolve(returnedComputer.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
