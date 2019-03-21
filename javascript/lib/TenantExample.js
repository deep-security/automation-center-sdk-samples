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
 * Creates a tenant.
 * @param {object} api The api module.
 * @param {String} accountName The account name to use for the tenant.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the new tentant.
 */
exports.createTenant = function(api, accountName, apiVersion) {
  return new Promise((resolve, reject) => {
    // Tenant object
    const tenant = new api.Tenant();

    // Set the visible modules
    tenant.modulesVisible = [
      api.Tenant.ModulesVisibleEnum["anti-malware"],
      api.Tenant.ModulesVisibleEnum.firewall,
      api.Tenant.ModulesVisibleEnum["intrusion-prevention"]
    ];

    // Set the account name
    tenant.name = accountName;

    // Define the administrator account
    const admin = new api.Administrator();
    admin.username = "MasterAdmin";
    admin.password = "P@55word";
    admin.emailAddress = "example@email.com";
    tenant.administrator = admin;

    // Set the locale and description
    tenant.locale = api.Tenant.LocaleEnum["en-US"];
    tenant.description = "Test tenant.";

    // Creates the tenant
    const createTenant = () => {
      const tenantsApi = new api.TenantsApi();
      return tenantsApi.createTenant(tenant, apiVersion, {
        confirmationRequired: "false",
        asynchronous: "true"
      });
    };

    createTenant()
      .then(newTenant => {
        resolve(newTenant);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Obtains the running state of the Intrusion Prevention module for a tenant's computers.
 * @param {object} api The api module.
 * @param {Number} tenantID The ID of the tenant.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains computer IDs and the module running state.
 */
exports.getIPStatesForTenant = function(api, tenantID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Stores the Intrusion Prevention states
    const computerIPStates = [];

    // Creates an API key
    const createKey = () => {
      // ApiKey properties
      const key = new api.ApiKey();
      key.keyName = "Temporary Key";
      key.roleID = 1;
      key.locale = api.ApiKey.LocaleEnum["en-US"];
      key.timeZone = "Asia/Tokyo";

      const tenantsApi = new api.TenantsApi();
      return tenantsApi.generateTenantApiSecretKey(tenantID, key, apiVersion);
    };

    // Gets a list of tenant computers
    const getComputers = apiClient => {
      const computersApi = new api.ComputersApi(apiClient);
      return computersApi.listComputers(apiVersion, { overrides: "false" });
    };

    // Deletes an ApiKey from a tenant
    const deleteKey = (apiClient, keyID) => {
      const apiKeysApi = new api.APIKeysApi();
      apiKeysApi.deleteApiKey(keyID, apiVersion).catch(error => {
        console.log(error);
      });
    };

    // Configure the ApiClient for connecting to the tenant
    const tenantClient = api.ApiClient.instance;
    const defaultAuthentication = tenantClient.authentications["DefaultAuthentication"];
    let tenantKey;

    createKey()
      .then(newKey => {
        tenantKey = newKey;
        defaultAuthentication.apiKey = newKey.secretKey;
        return getComputers(tenantClient);
      })
      .then(computers => {
        // Get the state of Intrusion Prevention module for each computer
        for (let i = 0; i < computers.computers.length; i++) {
          computerIPStates[i] = {
            ID: computers.computers[i].ID,
            IpState: computers.computers[i].intrusionPrevention.state
          };
        }
        deleteKey(tenantClient, tenantKey.ID);
        resolve(computerIPStates);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Obtains the IDs of the Intrusion Prevention rules that are assigned to each tenant's computers.
 * Care must be taken to ensure that ApiClient uses the correct Api Key
 * when iterating tenants and calling asynchronous functions.
 * @param {object} api The api module.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains, for each tenant, computer IDs and the rule IDs.
 */
exports.getIpRulesForTenantComputers = function(api, apiVersion, secretKey) {
  return new Promise((resolve, reject) => {
    let tenantRules, tenantKeys;
    const keyPromises = [];
    const rulePromises = [];
    const deleteKeyPromises = [];

    // Search for active tenants
    const tenantsApi = new api.TenantsApi();

    // Search criteria
    const searchCriteria = new api.SearchCriteria();
    searchCriteria.fieldName = "tenantState";
    searchCriteria.choiceTest = api.SearchCriteria.ChoiceTestEnum.equal;
    searchCriteria.choiceValue = "active";

    // Search filter
    const searchFilter = new api.SearchFilter();
    searchFilter.searchCriteria = [searchCriteria];

    // Search options
    const searchOptions = {
      searchFilter: searchFilter,
      overrides: false
    };

    // Perform the search
    tenantsApi
      .searchTenants(apiVersion, searchOptions)
      .then(tenants => {
        const tenantsList = tenants.tenants;

        // Create an API Key for each tenant
        // Store each promise in an array
        for (let i = 0; i < tenantsList.length; i++) {
          keyPromises.push(createKey(tenantsList[i].ID, api, apiVersion));
        }
        // Continue when all promises are resolved
        return Promise.all(keyPromises);
      })
      .then(keyObjects => {
        tenantKeys = keyObjects;
        // For each tenant, get the IP rules for all computers
        // Store each promise in an array
        keyObjects.forEach(keyObject => {
          rulePromises.push(getComputers(keyObject.apiKey, keyObject.tenantID, api, apiVersion));
        });
        //Continue when all promises are resolved
        return Promise.all(rulePromises);
      })
      .then(ruleListObjects => {
        tenantRules = ruleListObjects;
        // Delete each tenant key
        // Store each promise in an array
        tenantKeys.forEach(tenantKey => {
          deleteKeyPromises.push(deleteKey(tenantKey.apiKey, api, apiVersion));
        });
        // Continue when all promises are resolved
        return Promise.all(deleteKeyPromises);
      })
      .then(() => {
        // Configure ApiClient to use the primary tenant's API Key before returning
        const apiClient = api.ApiClient.instance;
        const DefaultAuthentication = apiClient.authentications["DefaultAuthentication"];
        DefaultAuthentication.apiKey = secretKey;

        // Return the rule IDs
        resolve(tenantRules);
      })
      .catch(error => {
        reject(error);
      });
  });
};

// ### PRIVATE FUNCTIONS

// Creates an API key for a tenant
function createKey(tenantID, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // ApiKey properties
    const key = new api.ApiKey();
    key.keyName = "Temporary sKey";
    key.roleID = 1;
    key.locale = api.ApiKey.LocaleEnum["en-US"];
    key.timeZone = "Asia/Tokyo";

    // Create the key
    const tenantsApi = new api.TenantsApi();
    tenantsApi
      .generateTenantApiSecretKey(tenantID, key, apiVersion)
      .then(key => {
        // Return an object that contains the key and the tenant ID
        resolve({ tenantID: tenantID, apiKey: key });
      })
      .catch(error => {
        reject(error);
      });
  });
}

// Gets a list of tenant computers and then gets the Intrusion Prevention rule IDs for each computer
function getComputers(tenantKey, tenantID, api, apiVersion) {
  return new Promise((resolve, reject) => {
    const computerIPRules = []; //Stores the rule ID's

    // Configure ApiClient
    const tenantClient = api.ApiClient.instance;
    const DefaultAuthentication = tenantClient.authentications["DefaultAuthentication"];
    DefaultAuthentication.apiKey = tenantKey.secretKey;

    // Get the computers from the tenant
    const computersApi = new api.ComputersApi();
    computersApi
      .listComputers(apiVersion, { overrides: "false" })
      .then(computers => {
        // Get the Intrusion Prevention rules for each computer
        for (let i = 0; i < computers.computers.length; i++) {
          // Store as objects that contain the computer ID and the rule IDs
          computerIPRules.push({
            ID: computers.computers[i].ID,
            IpRules: computers.computers[i].intrusionPrevention.ruleIDs
          });
        }
        // Return an object that contains the tenant ID and the array of computer and rule IDs
        resolve({ tenantID: tenantID, IPRules: computerIPRules });
      })
      .catch(error => {
        reject(error);
      });
  });
}

// Deletes an ApiKey from a tenant
function deleteKey(tenantKey, api, apiVersion) {
  // Configure ApiClient;
  const tenantClient = api.ApiClient.instance;
  const DefaultAuthentication = tenantClient.authentications["DefaultAuthentication"];
  DefaultAuthentication.apiKey = tenantKey.secretKey;
  // Delete the key
  const apiKeysApi = new api.APIKeysApi();
  return apiKeysApi.deleteApiKey(tenantKey.ID, apiVersion);
}

/*
 * Adds a policy to a tenant.
 * @param {object} api The api module.
 * @param {Object} policy The policy to add to the tenant.
 * @param {Number} tenantID The ID of the tenant.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A promise that contains the new policy.
 */
exports.addPolicyToTenant = function(api, policy, tenantID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Creates an API key
    const createKey = () => {
      // ApiKey properties
      const key = new api.ApiKey();
      key.keyName = "Test Key";
      key.roleID = 1;
      key.locale = api.ApiKey.LocaleEnum["en-US"];
      key.timeZone = "Asia/Tokyo";
      const tenantsApi = new api.TenantsApi();
      return tenantsApi.generateTenantApiSecretKey(tenantID, key, apiVersion);
    };

    // Adds a policy to the tenant
    const addPolicy = apiClient => {
      const policiesApi = new api.PoliciesApi(apiClient);
      return policiesApi.createPolicy(policy, apiVersion, { overrides: false });
    };

    // Deletes an ApiKey from a tenant
    const deleteKey = (apiClient, keyID) => {
      const apiKeysApi = new api.APIKeysApi();
      apiKeysApi.deleteApiKey(keyID, apiVersion).catch(error => {
        console.log(error);
      });
    };

    // ApiClient for connecting to the tenant
    const tenantClient = api.ApiClient.instance;
    const DefaultAuthentication = tenantClient.authentications["DefaultAuthentication"];
    let tenantKey;
    createKey()
      .then(newKey => {
        tenantKey = newKey;
        DefaultAuthentication.apiKey = newKey.secretKey;
        return addPolicy(tenantClient);
      })
      .then(newPolicy => {
        deleteKey(tenantClient, tenantKey.ID);
        resolve(newPolicy);
      })
      .catch(error => {
        reject(error);
      });
  });
};
