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
 * Obtains agent and appliance status for all comptuters
 * and provides the results as comma-separated values.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains a string of values in CSV format.
 */
exports.getComputerStatuses = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Obtains a list of all computers
    const getListOfComputers = () => {
      const computersApi = new api.ComputersApi();
      return computersApi.listComputers(apiVersion, { overrides: false });
    };
    // Add column titles to comma-separated values string
    let csv = "Host Name, Agent or Appliance, Status, Status Messages, Tasks\r\n";
    // Get the computers and iterate them
    getListOfComputers()
      .then(computers => {
        for (const computer of computers.computers) {
          const computerInfo = []; // Stores computer status information
          // Report on computers with no agent or appliance
          if ((computer.agentFingerPrint === undefined) & (computer.applianceFingerPrint === undefined)) {
            // Hostname and protection type
            computerInfo.push(computer.hostName);
            computerInfo.push("None");
            // Agent/appliance status and status message
            computerInfo.push("No agent/appliance");
            computerInfo.push(
              computer.computerStatus.agentStatus !== undefined ? computer.computerStatus.agentStatusMessages : ""
            );
            // Add to CSV string
            csv += formatForCSV(computerInfo);
          } else {
            // Report on problem agents and appliances
            const agentIsActive = computer.computerStatus.agentStatus == api.ComputerStatus.AgentStatusEnum.active;
            const applianceIsActive =
              computer.computerStatus.applianceStatus == api.ComputerStatus.ApplianceStatusEnum.active;
            if (computer.agentFingerPrint !== undefined && !agentIsActive) {
              // Agent is installed but not active
              computerInfo.push(computer.hostName);
              computerInfo.push("Agent");
              computerInfo.push(
                computer.computerStatus.agentStatus !== undefined ? computer.computerStatus.agentStatus : ""
              );
              computerInfo.push(
                computer.computerStatus.agentStatusMessages !== undefined
                  ? computer.computerStatus.agentStatusMessages
                  : ""
              );
              computerInfo.push(computer.tasks !== undefined ? computer.tasks.agentTasks : "");
              // Add to CSV string
              csv += formatForCSV(computerInfo);
              computerInfo.lenght = 0;
            }
            if (computer.applianceFingerPrint !== undefined && !applianceIsActive) {
              // Appliance is installed but not active
              computerInfo.push(computer.hostName);
              computerInfo.push("Appliance");
              computerInfo.push(
                computer.computerStatus.applianceStatus !== undefined ? computer.computerStatus.applianceStatus : ""
              );
              computerInfo.push(
                computer.computerStatus.applianceStatusMessages !== undefined
                  ? computer.computerStatus.applianceStatusMessages
                  : ""
              );
              computerInfo.push(computer.tasks !== undefined ? computer.tasks.applianceTasks : "");
              // Add to CSV string
              csv += formatForCSV(computerInfo);
            }
          }
        }
        resolve(csv);
      })
      .catch(error => {
        reject(error);
      });
  });
};

exports.getAntiMalwareStatusForComputers = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Obtains a list of all computers
    const getListOfComputers = () => {
      const computersApi = new api.ComputersApi();
      return computersApi.listComputers(apiVersion, { overrides: false });
    };
    // Add column titles to comma-separated values string
    let csv = "Host Name, Module State, Agent or Appliance, Status, Status Message\r\n";
    // Get the computers and iterate them
    getListOfComputers()
      .then(computers => {
        for (const computer of computers.computers) {
          let moduleInfo = [];
          const agentStatus = computer.antiMalware.moduleStatus.agentStatus;
          const applianceStatus = computer.antiMalware.moduleStatus.applianceStatus;

          // Agents that are not active for the module
          if (agentStatus !== undefined && agentStatus !== api.ComputerModuleStatus.AgentStatusEnum.active) {
            // Hostname
            moduleInfo.push(computer.hostName);
            // Module state
            moduleInfo.push(computer.antiMalware.state);
            // Agent status and status message
            moduleInfo.push("Agent");
            moduleInfo.push(agentStatus);
            moduleInfo.push(computer.antiMalware.moduleStatus.agentStatusMessages);

            // Add to the CSV string
            csv += formatForCSV(moduleInfo);
            moduleInfo.length = 0;
          }
          // Appliances that are not active for the module
          if (applianceStatus !== undefined && agentStatus !== api.ComputerModuleStatus.ApplianceStatusEnum.active) {
            // Hostname
            moduleInfo.push(computer.hostName);
            // Module state
            moduleInfo.push(computer.antiMalware.state);
            // Agent status and status message
            moduleInfo.push("Appliance");
            moduleInfo.push(applianceStatus);
            moduleInfo.push(computer.antiMalware.moduleStatus.applianceStatusMessages);

            // Add to the CSV string
            csv += formatForCSV(moduleInfo);
          }
        }
        resolve(csv);
      })
      .catch(error => {
        reject(error);
      });
  });
};

// PRIVATE METHODS //

/*
 * Converts an array of string values into a string of comma-separated values.
 * @param {Array} values The array of values.
 * @return {String} The string of comma-separated values.
 */
function formatForCSV(values) {
  let csvLine = "";
  for (let i = 0; i < values.length; i++) {
    csvLine += '"' + values[i] + '"';
    if (i != values.length - 1) {
      csvLine += ",";
    } else {
      csvLine += "\r\n";
    }
  }
  return csvLine;
}

/*
 * Obtains certain Anti-Malware properties for a computer.
 * @param {object} api The api module.
 * @param {Number} computerID The ID of the computer.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains on object of Anti-Malware properties.
 */

exports.checkAntiMalware = function(api, computerID, apiVersion) {
  return new Promise((resolve, reject) => {
    let amStatus, computer;

    // Gets the computer object from Deep Security Manager
    const getComputer = () => {
      const computersApi = new api.ComputersApi();
      return computersApi.describeComputer(computerID, apiVersion, {
        overrides: false
      });
    };

    // Gets the malware scan configuration for a computer
    const getMalwareScanConfig = computerObj => {
      const realTimeScanConfigID = computerObj.antiMalware.realTimeScanConfigurationID;
      const amConfigsApi = new api.AntiMalwareConfigurationsApi();
      return amConfigsApi.describeAntiMalware(realTimeScanConfigID, apiVersion);
    };

    getComputer()
      .then(computerObj => {
        computer = computerObj;
        amStatus = getAntiMalwareInfo(computerObj);
        if (computerObj.antiMalware.realTimeScanConfigurationID !== 0) {
          getMalwareScanConfig(computerObj)
            .then(scanConfig => {
              amStatus.directoriesToScan = scanConfig.directoriesToScan;
              resolve(amStatus);
            })
            .catch(error => {
              reject(error);
            });
        } else {
          resolve(amStatus);
        }
      })
      .catch(error => {
        reject(error);
      });
  });
};

// PRIVATE METHODS //

// Retrieves certain Anti-Malware properties from a computer object
function getAntiMalwareInfo(computer) {
  const status = {};
  status.name = computer.hostName;
  status.state = computer.antiMalware.state;
  status.smartScanErrorEnabled = computer.computerSettings.antiMalwareSettingSmartScanState;
  return status;
}

/*
 * Finds the Intrusion Prevention rules that protect against a CVE.
 * @param {object} api The api module.
 * @param {Number} cveID The ID of the CVE (for example CVE-2016-7214) or
 *    part of the ID (for example CVE-2016 or 7214).
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the rule IDs.
 */
exports.findRulesForCVE = function(api, cveID, apiVersion) {
  const ruleIDs = [];

  // Search for Intrusion Prevention rules
  return new Promise((resolve, reject) => {
    const getIpRules = () => {
      // Search criteria
      const cveCriteria = new api.SearchCriteria();
      cveCriteria.fieldName = "CVE";
      cveCriteria.stringValue = "%" + cveID + "%";
      cveCriteria.stringTest = api.SearchCriteria.StringTestEnum.equal;

      // Add criteria to a search filter
      const searchFilter = new api.SearchFilter();
      searchFilter.searchCriteria = [cveCriteria];

      // Add the search filter to a search options object
      const searchOptions = {
        searchFilter: searchFilter,
        overrides: false
      };

      // Perform the search
      const ipRulesApi = new api.IntrusionPreventionRulesApi();
      return ipRulesApi.searchIntrusionPreventionRules(apiVersion, searchOptions);
    };

    getIpRules()
      .then(ipRules => {
        // Iterate the rules and get the IDs
        for (let i = 0; i < ipRules.intrusionPreventionRules.length; i++) {
          ruleIDs.push(ipRules.intrusionPreventionRules[i].ID);
        }
        resolve(ruleIDs);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Finds computers that are not assigned a specific Intrusion Prevention rule.
 * @param {object} api The api module.
 * @param {Number} ruleID The ID of the rule.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains an array of IDs of unprotected computers.
 */
exports.checkComputersForIPRule = function(api, ruleID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Retrieves computers from Deep Security Manager
    const getComputers = () => {
      const computersApi = new api.ComputersApi();
      return computersApi.listComputers(apiVersion, { overrides: false });
    };

    // Finds computers that are not assigned the rule
    const checkForRule = function(computers) {
      let unprotected = [];
      for (let i = 0; i < computers.computers.length; i++) {
        if (computers.computers[i].intrusionPrevention !== undefined) {
          const IDs = computers.computers[i].intrusionPrevention.ruleIDs;
          let found = false;
          if (IDs !== undefined) {
            for (let j = 0; j < IDs.length; j++) {
              if (IDs[j] === ruleID) {
                found = true;
                break;
              }
            }
          }
          if (!found) {
            unprotected.push(computers.computers[i]);
          }
        }
      }
      return unprotected;
    };

    getComputers()
      .then(computerlist => {
        resolve(checkForRule(computerlist));
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Assigns an Intrusion Prevention rule to the policy that is assigned to a computer.
 * @param {object} api The api module.
 * @param {Computer} computer The Computer that is assigned a policy.
 * @param {number} ruleID The ID of the Intrusion Prevention rule to add.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the modified policy.
 */

exports.applyRuleToPolicy = function(api, computer, ruleID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Retrieves the policy that we are modifying
    const getPolicy = policyID => {
      const policiesApi = new api.PoliciesApi();
      return policiesApi.describePolicy(policyID, apiVersion, {
        overrides: false
      });
    };

    // Creates a policy that includes the Intrusion Prevention rules
    // Rule is added to the currently assigned rules so they are not overwritten
    const addRulesToPolicyObject = currentRules => {
      if (currentRules !== undefined) {
        currentRules.push(ruleID);
      } else {
        currentRules = [ruleID];
      }
      const intrusionPreventionPolicyExtension = new api.IntrusionPreventionPolicyExtension();
      intrusionPreventionPolicyExtension.ruleIDs = currentRules;

      const policy = new api.Policy();
      policy.intrusionPrevention = intrusionPreventionPolicyExtension;
      policy.autoRequiresUpdate = api.Policy.AutoRequiresUpdateEnum.on;
      return policy;
    };

    // Updates the policy on Deep Security Manager
    const sendPolicyToManager = (policyID, policy) => {
      const policiesApi = new api.PoliciesApi();
      return policiesApi.modifyPolicy(policyID, policy, apiVersion, {
        overrides: false
      });
    };

    // Check that the computer is assigned a policy
    if (computer.policyID === undefined) {
      reject("Computer has no policy");
      return;
    }
    getPolicy(computer.policyID)
      .then(policy => {
        const newPolicy = addRulesToPolicyObject(policy.intrusionPrevention.ruleIDs);
        resolve(sendPolicyToManager(computer.policyID, newPolicy));
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Obtains the list of recommended Intrusion Prevention rules to apply to a computer,
 * according to the results of the last recommendation scan.* @param {object} api The api module.
 * @param {object} api The api module.
 * @param {Computer} computer The Computer that was scanned.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the recommended rules.
 */
exports.getRecommendedIPRules = function(api, computerID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Obtains the results of the recommendation scan
    const getRecommendations = () => {
      const ipRecosApi = new api.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi();
      return ipRecosApi.listIntrusionPreventionRuleIDsOnComputer(computerID, apiVersion, { overrides: false });
    };

    getRecommendations()
      .then(ipAssignments => {
        // Resolve the recommended rules
        resolve(ipAssignments.assignedRuleIDs);
      })
      .catch(error => {
        reject(error);
      });
  });
};
