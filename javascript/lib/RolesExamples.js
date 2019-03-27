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
 * Searches for a role by name and returns the ID.
 * @param {String} roleName The role name to search for.
 * @param {object} api The api module.
 * @param {String} apiVersion The API version to use.
 * @return {Promise} A promise that contains the ID of the found role or undefined if not found.
 */
exports.searchRolesByName = function(roleName, api, apiVersion) {
  return new Promise((resolve, reject) => {
    let newRoleID; // Stores the role ID -- default is undefined

    // Search criteria
    const nameCriteria = new api.SearchCriteria();
    nameCriteria.fieldName = "name";
    nameCriteria.stringValue = roleName;
    nameCriteria.stringTest = api.SearchCriteria.StringTestEnum.equal;

    // Search filter
    const roleFilter = new api.SearchFilter();
    roleFilter.searchCriteria = [nameCriteria];

    // Search options
    const searchOptions = {
      searchFilter: roleFilter,
      overrides: false
    };

    // Perform the search
    const adminRolesApi = new api.AdministratorRolesApi();
    adminRolesApi
      .searchAdministratorRoles(apiVersion, searchOptions)
      .then(returnedRoles => {
        // Resolve the role ID
        if (returnedRoles.roles.length > 0) {
          newRoleID = returnedRoles.roles[0].ID;
        }
        resolve(newRoleID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Creates a role with rights that are appropriate for reading computer properties and assigning policies to computers.
 * @param {object} api The api module.
 * @param {String} apiVersion The API version to use.
 * @return {Promise} A promise that contains the ID of the new role.
 */
exports.createRoleForComputerReports = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the Role object
    const runReportsRole = new api.Role();
    runReportsRole.name = "Computer Status and Properties";

    // No need for access to policies
    runReportsRole.allPolicies = false;

    // Add rights to edit computer properties
    const computerRights = new api.ComputerRights();
    computerRights.canEditComputerProperties = true;

    const platformRights = new api.PlatformRights();
    platformRights.computerRights = computerRights;

    const rights = new api.Rights();
    rights.platformRights = platformRights;

    // Add the rights to the role
    runReportsRole.rights = rights;

    // Create the role on Deep Security Manager
    const adminRolesApi = new api.AdministratorRolesApi();
    adminRolesApi
      .createAdministratorRole(runReportsRole, apiVersion)
      .then(newRole => {
        resolve(newRole.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
