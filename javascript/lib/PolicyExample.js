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
 * Creates a policy that inherits from the Base Policy.
 * @param {Object} api The Deep Security API modules.
 * @param {String} policyName The name of the new policy.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the new policy.
 */
exports.createPolicy = function(api, policyName, apiVersion) {
  return new Promise((resolve, reject) => {
    const policiesApi = new api.PoliciesApi();

    // Create the policy object and set properties
    const newPolicy = new api.Policy();
    newPolicy.name = policyName;
    newPolicy.description = "Inherits from Base Policy";
    newPolicy.recommendationScanMode = api.Policy.RecommendationScanModeEnum.off;
    newPolicy.autoRequiresUpdate = api.Policy.AutoRequiresUpdateEnum.on;

    // Create a search criteria to find the Base Policy
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.fieldName = "name";
    searchCriteria.stringValue = "Base Policy";
    searchCriteria.stringTest = "equal";

    // Create a search filter
    const searchFilter = new api.SearchFilter();
    searchFilter.searchCriteria = [searchCriteria];

    // Add the search filter  to a search options object
    const searchOptions = {
      searchFilter: searchFilter
    };

    // Performs the search
    const searchPolicy = () => policiesApi.searchPolicies(apiVersion, searchOptions);
    // Add the policy to Deep Security Manager
    const createPolicy = data => {
      newPolicy.parentID = data.policies[0].ID;
      return policiesApi.createPolicy(newPolicy, apiVersion, { overrides: false });
    };

    searchPolicy()
      .then(createPolicy)
      .then(data => {
        resolve(data.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Assign a Linux server policy to a computer.
 * @param {Object} api The Deep Security API modules.
 * @param {Number} computerID The ID of the computer to assign the policy.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the modified computer object.
 */
exports.assignLinuxServerPolicy = function(api, computerID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the search criteria
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.fieldName = "name";
    searchCriteria.stringValue = "%Linux Server%";
    searchCriteria.stringTest = "equal";
    searchCriteria.stringWildcards = "true";

    // Create a search filter
    const searchFilter = new api.SearchFilter();
    searchFilter.searchCriteria = [searchCriteria];

    const policiesApi = new api.PoliciesApi();

    // Searches for the policy
    const searchPolicy = () => policiesApi.searchPolicies(apiVersion, searchFilter);

    const computersApi = new api.ComputersApi();

    // Assigns the found policy to the computer
    const assignPolicy = searchResults => {
      const computer = new api.Computer();
      computer.policyID = searchResults.policies[0].ID;
      return computersApi.modifyComputer(computerID, computer, apiVersion, { overrides: false });
    };

    searchPolicy()
      .then(assignPolicy)
      .then(data => {
        resolve(data);
      })
      .catch(error => {
        reject(error);
      });
  });
};
/*
 * Resets all but the Alert Minimum Severity and Recommendation Options overrides
 * of a Log Inspection rule that is assigned to a policy.
 * @param {Number} policyID The ID of the policy that is assigned the rule.
 * @param {Number} ruleID The ID of the Log Inspection rule.
 * @param {Object} api The Deep Security API modules.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the updated rule.
 */
exports.selectiveResetForLogInspectionRuleOnPolicy = function(policyID, ruleID, api, apiVersion) {
  return new Promise((resolve, reject) => {
    let ruleWithOverrides; // Stores the rule with overrides

    // Retrieves the overridden properties of the Log Inspection rule that is assigned the policy
    const getRule = () => {
      const policyLogInspectionRuleDetailsApi = new api.PolicyLogInspectionRuleDetailsApi();
      return policyLogInspectionRuleDetailsApi.describeLogInspectionRuleOnPolicy(policyID, ruleID, apiVersion, {
        overrides: true
      });
    };

    // Resets the overridden properties of the rule that is assigned to the policy
    const resetRule = () => {
      const policyLogInspectionRuleDetailsApi = new api.PolicyLogInspectionRuleDetailsApi();
      return policyLogInspectionRuleDetailsApi.resetLogInspectionRuleOnPolicy(policyID, ruleID, apiVersion, {
        overrides: false
      });
    };

    // Overrides the rule that is assigned to the policy according to the given rule's properties
    const updateRule = rule => {
      const policyLogInspectionRuleDetailsApi = new api.PolicyLogInspectionRuleDetailsApi();
      return policyLogInspectionRuleDetailsApi.modifyLogInspectionRuleOnPolicy(policyID, ruleID, rule, apiVersion, {
        overrides: false
      });
    };

    // Get the Log Inspection rule (overridden properties only) that is assigned to the policy
    getRule()
      .then(liRule => {
        // Store the rule
        ruleWithOverrides = liRule;
        // Reset the rule on the policy
        return resetRule();
      })
      .then(() => {
        // Create a Log Inpsection rule
        let liRuleWithOverridesRestored = new api.LogInspectionRule();

        // Set the properties of the new rule to restore the desired overrides
        if (ruleWithOverrides.alertMinimumSeverity !== undefined) {
          liRuleWithOverridesRestored.alertMinimumSeverity = ruleWithOverrides.alertMinimumSeverity;
        }
        if (ruleWithOverrides.recommendationsMode !== undefined) {
          liRuleWithOverridesRestored.recommendationsMode = ruleWithOverrides.recommendationsMode;
        }
        // Update the rule for the policy with the desired overrides
        return updateRule(liRuleWithOverridesRestored);
      })
      .then(liRule => {
        resolve(liRule);
      })
      .catch(error => {
        reject(error);
      });
  });
};
