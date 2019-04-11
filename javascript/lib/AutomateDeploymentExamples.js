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
 * Configures the maximum number of active sessions.
 * Demonstrates how to configure system properties.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} The promise that SystemSettingsApi.modifySystemSettings returns.
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

/**
 * Creates a computer on Deep Security Manager.
 * @param {String} hostname The hostname or IP address that resolves to the computer.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise that contains the ID of the computer.
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

/**
 * Obtains an agent deployment script from Deep Security Manager according to the provided parameter values.
 *
 * @param {object} api The api module.
 * @param {String} apiVersion The API version to use.
 * @param {api.AgentDeploymentScript.PlatformEnum} platform The platform of the target computer.
 * @param {Number} dsmProxyID The ID of the proxy to use to connect to Deep Security Manager. The default is no proxy.
 * @param {Boolean} validateCertificate Determines whether to validate that Deep Security Manager is using a valid TLS certificate from a trusted certificate authority (CA). The default is false.
 * @param {Boolean} activate True causes the script to activate the agent. The default is false.
 * @param {Number} computerGroupID The ID of the computer group to which the computer is added. The default is no computer group.
 * @param {Number} policyID The ID of the policy to assign to the computer. The default is no policy.
 * @param {Number} relayID The ID of the relay to assign to the computer for obtaining updates. The default is no relay.
 * @param {Number} relayProxyID The ID of the proxy that the agent uses to connect to the relay. The default is no proxy.
 * @returns {Promise} A promise that contains the deployment script.
 */
exports.getAgentDeploymentScript = function(
  api,
  apiVersion,
  platform,
  dsmProxyID = null,
  validateCertificate = null,
  activate = null,
  computerGroupID = null,
  policyID = null,
  relayID = null,
  relayProxyID = null
) {
  return new Promise((resolve, reject) => {
    // Create the AgentDeploymentScript object and configure
    const deploymentScript = new api.AgentDeploymentScript();
    deploymentScript.platform = platform;
    deploymentScript.dsmProxyID = dsmProxyID;
    deploymentScript.validateCertificateRequired = validateCertificate;
    deploymentScript.activationRequired = activate;
    deploymentScript.computerGroupID = computerGroupID;
    deploymentScript.policyID = policyID;
    deploymentScript.relayID = relayID;
    deploymentScript.relayProxyID = relayProxyID;

    // Add the AgentDeploymentScript to an object
    const options = {
      agentDeploymentScript: deploymentScript
    };

    // Obtain the agent deployment script from Deep Security Manager and return the script
    const agentDeploymentScriptsApi = new api.AgentDeploymentScriptsApi();
    agentDeploymentScriptsApi
      .generateAgentDeploymentScript(apiVersion, options)
      .then(returnedAgentDeploymentScriptObject => {
        resolve(returnedAgentDeploymentScriptObject.scriptBody);
      })
      .catch(error => {
        reject(error);
      });
  });
};
