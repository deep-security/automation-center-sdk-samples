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

exports.searchFirewallRules = function(hostUrl, apiSecretKey) {
  return new Promise((resolve, reject) => {
    // Deep Security module
    const api = require("@trendmicro/deepsecurity");

    // Create the client
    const defaultClient = api.ApiClient.instance;
    defaultClient.basePath = hostUrl;
    const defaultAuthentication = defaultClient.authentications["DefaultAuthentication"];
    defaultAuthentication.apiKey = apiSecretKey;

    // Allow connection that is 'secured' with self-signed certificate - for development only
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    // Define the search criteria
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.fieldName = "name";
    searchCriteria.stringValue = "%DHCP%";
    searchCriteria.stringTest = api.SearchCriteria.StringTestEnum.equal;
    searchCriteria.stringWildcards = true;

    // Create a search filter to find the rule
    const searchFilter = new api.SearchFilter();
    searchFilter.searchCriteria = [searchCriteria];

    // Add the search filter to a search options object
    const searchOptions = {
      searchFilter: searchFilter,
      overrides: false
    };

    // Create a FirewallRulesApi object
    const fwRulesApi = new api.FirewallRulesApi();

    // Perform the search and handle the returned promise
    fwRulesApi
      .searchFirewallRules("v1", searchOptions)
      .then(data => {
        resolve(data.firewallRules);
      })
      .catch(error => {
        reject(error);
      });
  });
};
