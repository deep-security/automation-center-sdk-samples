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
 * Modifies a policy to set the Application Control state to ON.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} policyID The ID of the policy to modify.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the modified policy.
*/
exports.configureApplicationControl = function (api, policyID, apiVersion) {
  return new Promise((resolve, reject) => {
    const policy = new api.Policy();
    const policiesApi = new api.PoliciesApi();
    const appControlPolicyExtension = new api.ApplicationControlPolicyExtension();

    //Turn on application control
    appControlPolicyExtension.state =
      api.ApplicationControlPolicyExtension.StateEnum.on;

    //Add to the policy
    policy.applicationControl = appControlPolicyExtension;

    //Send the change to Deep Security Manager
    policiesApi.modifyPolicy(policyID, policy, apiVersion, { overrides: false })
      .then(data => {
        resolve(data);
      })
      .catch(function (error) {
        reject(error);
      });
  });
};

/*
 * Blocks all software changes on a computer.
 * @param {Number} computerID The ID of the computer.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise object that resolves to an Array of SoftwareChangeReviewResult objects.
 */
exports.blockAllUnrecognizedSoftware = function (computerID, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Search for software changes on the computer
    // Search criteria
    const computerCriteria = new api.SearchCriteria();
    computerCriteria.fieldName = "computerID";
    computerCriteria.numericTest = api.SearchCriteria.NumericTestEnum.equal;
    computerCriteria.numericValue = computerID;

    // Add criteria to search filter
    const searchFilter = new api.SearchFilter();
    searchFilter.searchCriteria = [computerCriteria];

    // Add search filter to a search options object
    const searchOptions = {
      searchFilter: searchFilter
    };

    // Perform the search
    const softwareChangeApi = new api.SoftwareChangesApi();
    softwareChangeApi.searchSoftwareChanges(apiVersion, searchOptions)
      .then(results => {
        // Block the unrecognized software

        // Create the software change review object and set action to block
        const softwareChangeReview = new api.SoftwareChangeReview();
        softwareChangeReview.action = api.SoftwareChangeReview.ActionEnum.block;

        if (results.softwareChanges.length > 0) {
          // Add the IDs of the software changes to block
          softwareChangeReview.softwareChangeIDs = results.softwareChanges.map(softwareChange => softwareChange.ID);

          // Perform the software change review
          softwareChangeApi.reviewSoftwareChanges(softwareChangeReview, apiVersion)
            .then(softwareChangeReview => {
              resolve(softwareChangeReview.softwareChangeReviewResults);
            })
            .catch(error => {
              reject(error);
            });
        } else {
          resolve(results);
        }
      })
      .catch(error => {
        reject(error);
      })
  });
};

/*
 * Creates a shared ruleset from a computer's software inventory
 * @param {Number} computerID The ID of the computer whose inventory the ruleset should be created from.
 * @param {String} rulesetName The name of the ruleset.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise object that resolves to a Ruleset object.
 */
exports.createSharedRuleset = function(computerID, rulesetName, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create a software inventory
    const softwareInventory = new api.SoftwareInventory();
    softwareInventory.computerID = computerID;
    
    const softwareInventoryApi = new api.SoftwareInventoriesApi();
    softwareInventoryApi.createSoftwareInventory(softwareInventory, apiVersion)
      .then(softwareInventory => {
        // Wait until the software inventory is done building
        function waitForInventoryBuild() {
          softwareInventoryApi.describeSoftwareInventory(softwareInventory.ID, apiVersion)
            .then(softwareInventory => {
              if (softwareInventory.state === api.SoftwareInventory.StateEnum.complete) {
                // Create a ruleset
                const ruleset = new api.Ruleset();
                ruleset.name = rulesetName;

                const rulesetApi = new api.RulesetsApi();
                rulesetApi.createRuleset(ruleset, softwareInventory.ID, apiVersion)
                  .then(ruleset => {
                    return resolve(ruleset);
                  })
                  .catch(error => {
                    return reject(error);
                  });
              } else {
                //Check every 30 seconds
                setTimeout(waitForInventoryBuild, 30000);
              }
            })
            .catch(error => {
              return reject(error);
            });
        }
        waitForInventoryBuild();
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Adds new Global Rules
 * @param {Array} sha256List The list of SHA-256 hashes of the executables to create new rules for.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise object that resolves to an Array of ApplicationControlGlobalRule objects.
 */
exports.addGlobalRules = function (sha256List, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the rules
    const globalRules = new api.ApplicationControlGlobalRules();
    globalRules.applicationControlGlobalRules = sha256List.map(sha256 => {
      const newRule = new api.ApplicationControlGlobalRule();
      newRule.sha256 = sha256;
      return newRule;
    });

    // Add the rules
    const globalRuleApi = new api.GlobalRulesApi();
    globalRuleApi.addGlobalRules(globalRules, apiVersion)
    .then(rules => {
      resolve(rules);
    })
    .catch(error => {
      reject(error);
    });
  });
};

/*
 * Turn on maintenance mode on a computer.
 * @param {Number} computerID The ID of the computer.
 * @param {Number} duration The maintenance mode duration in milliseconds.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise object that resolves to a Computer object. 
 */
exports.turnOnMaintenanceMode = function (computerID, duration, api, apiVersion) {
  // Create and configure an ApplicationControlComputerExtension
  const applicationControl = new api.ApplicationControlComputerExtension();
  applicationControl.maintenanceModeStatus = api.ApplicationControlComputerExtension.MaintenanceModeStatusEnum.on;
  applicationControl.maintenanceModeDuration = duration;

  // Add the ApplicationControlComputerExtension to a computer
  const computer = new api.Computer();
  computer.applicationControl = applicationControl;

  // Update the computer
  const computersApi = new api.ComputersApi();
  return computersApi.modifyComputer(computerID, computer, apiVersion);
}