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
 * Searches for a policy by name.
 * @param {object} api The api module.
 * @param {String} name The policy name to search for.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the found poliicies.
 */
exports.searchPoliciesByName = function(api, name, apiVersion) {
  return new Promise((resolve, reject) => {
    // Search criteria
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.fieldName = "name";
    searchCriteria.stringTest = api.SearchCriteria.StringTestEnum.equal;
    searchCriteria.stringValue = name;

    // Add criteria to search filter
    const searchFilter = new api.SearchFilter();
    searchFilter.maxItems = 1;
    searchFilter.searchCriteria = [searchCriteria];

    // Add search filter to a search options object
    const searchOptions = {
      searchFilter: searchFilter,
      overrides: false
    };

    // Perform the search
    const policiesApi = new api.PoliciesApi();
    policiesApi
      .searchPolicies(apiVersion, searchOptions)
      .then(policies => {
        resolve(policies);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Searches for computers that are assigned to a specific policy and relay list.
 * @param {object} api The api module.
 * @param {Number} relayListID The ID of the relay list.
 * @param {Number} policyID The policy ID.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the found computers.
 */
exports.getComputersWithPolicyAndRelayList = function(api, relayListID, policyID, apiVersion) {
  // Search criteria for the platform
  const relayCriteria = new api.SearchCriteria();
  relayCriteria.fieldName = "relayListID";
  relayCriteria.numericTest = api.SearchCriteria.NumericTestEnum.equal;
  relayCriteria.numericValue = relayListID;

  // Search criteria for the policy ID
  const policyCriteria = new api.SearchCriteria();
  policyCriteria.fieldName = "policyID";
  policyCriteria.numericTest = api.SearchCriteria.NumericTestEnum.equal;
  policyCriteria.numericValue = policyID;

  // Add search criteria to a SearchFilter
  const searchFilter = new api.SearchFilter();
  searchFilter.searchCriteria = [relayCriteria, policyCriteria];

  // Add search filter to a search options object
  const searchOptions = {
    searchFilter: searchFilter,
    overrides: false
  };

  // Perform the search and return the promise
  const computersApi = new api.ComputersApi();
  return computersApi.searchComputers(apiVersion, searchOptions);
};

/*
 * Searches for Intrusion Prevention rules that have been updated within a specific number of days.
 * @param {object} api The api module.
 * @param {Number} numDays The number of days within which the rules were updated.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the found rules.
 */
exports.searchUpdatedIntrusionPreventionRules = function(api, numDays, apiVersion) {
  // Time that rules were last updated
  const updateTime = Date.now() - numDays * 24 * 60 * 60 * 1000;

  // Search criteria for the date range
  const searchCriteria = new api.SearchCriteria();
  searchCriteria.fieldName = "lastUpdated";
  searchCriteria.firstDateValue = updateTime;
  searchCriteria.lastDateValue = Date.now();
  searchCriteria.firstDateInclusive = true;
  searchCriteria.lastDateInclusive = true;

  // Add search criteria to a SearchFilter
  const searchFilter = new api.SearchFilter();
  searchFilter.searchCriteria = [searchCriteria];

  // Add search filter to a search options object
  const searchOptions = {
    searchFilter: searchFilter,
    overrides: false
  };

  // Perform the search
  const ipRulesApi = new api.IntrusionPreventionRulesApi();
  return ipRulesApi.searchIntrusionPreventionRules(apiVersion, searchOptions);
};

/*
 * Searches for computers in pages of 10.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains an array of the pages of computers.
 */
exports.pagedSearchComputers = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    const results = [];
    const pageSize = 10;

    function getPageOfComputers(pageSearchOptions) {
      // Checks the search results to see if we're done
      function checkResults(searchResults) {
        // Get the ID of the last computer found, and the number found
        const lastID = searchResults.computers[searchResults.computers.length - 1].ID;
        const numFound = searchResults.computers.length;

        // Uncomment to see the page details as they are obtained
        //console.log(`last ID:  ${lastID}; numfound: ${numFound}`);

        results.push(searchResults.computers);

        // If the number found is less than the page size we are done
        if (numFound < pageSize) {
          return results;
        }
        // Search filter for the next page of computers
        const nextSearchCriteria = new api.SearchCriteria();
        nextSearchCriteria.idValue = lastID;
        nextSearchCriteria.idTest = api.SearchCriteria.IdTestEnum["greater-than"];

        const nextSearchFilter = new api.SearchFilter();
        nextSearchFilter.maxItems = pageSize;
        nextSearchFilter.searchCriteria = [nextSearchCriteria];

        // Add search filter to a search options object
        const nextSearchOpts = {
          searchFilter: nextSearchFilter,
          overrides: false
        };
        // Get the next page of computers
        return getPageOfComputers(nextSearchOpts);
      }
      // Perform the next search
      const computersApi = new api.ComputersApi();
      return computersApi.searchComputers(apiVersion, pageSearchOptions).then(checkResults);
    }

    // Search criteria for first page of computers
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.idValue = 0;
    searchCriteria.idTest = api.SearchCriteria.IdTestEnum["greater-than"];

    // Search filter with maximum returned items
    const computerSearchFilter = new api.SearchFilter();
    computerSearchFilter.maxItems = pageSize;
    computerSearchFilter.searchCriteria = [searchCriteria];

    // Add search filter to a search options object
    const searchOpts = {
      searchFilter: computerSearchFilter,
      overrides: false
    };

    // Perform the search
    getPageOfComputers(searchOpts)
      .then(results => {
        resolve(results);
      })
      .catch(error => {
        reject(error);
      });
  });
};
