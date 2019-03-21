/* 
 * Copyright 2019 Trend Micro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *	  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.trendmicro.deepsecurity.docs;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.AdministratorRolesApi;
import com.trendmicro.deepsecurity.model.AdministratorRoles;
import com.trendmicro.deepsecurity.model.ComputerRights;
import com.trendmicro.deepsecurity.model.PlatformRights;
import com.trendmicro.deepsecurity.model.Rights;
import com.trendmicro.deepsecurity.model.Role;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchFilter;

/**
 * Creates and interacts with Deep Security Manager roles.
 */
public class RolesExamples {

	/**
	 * Searches for a role by name.
	 * 
	 * @param roleName The role name to search.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching for the role.
	 * @returns The ID of the found role, or null if no role is found
	 */
	public static Integer searchRolesByName(String roleName, String apiVersion) throws ApiException {

		// Search criteria
		SearchCriteria nameCriteria = new SearchCriteria();
		nameCriteria.setFieldName("name");
		nameCriteria.setStringValue(roleName);
		nameCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);

		// Search filter
		SearchFilter roleFilter = new SearchFilter();
		roleFilter.addSearchCriteriaItem(nameCriteria);

		// Perform the search and obtain the ID of the returned role
		AdministratorRolesApi adminRolesApi = new AdministratorRolesApi();
		AdministratorRoles roles = adminRolesApi.searchAdministratorRoles(roleFilter, apiVersion);

		Integer roleId = null;
		if (!roles.getRoles().isEmpty()) {
			roleId = roles.getRoles().get(0).getID();
		}
		return roleId;
	}

	/**
	 * Creates a role with rights that are appropriate for reading computer properties and assigning policies to computers.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the role on Deep Security Manager.
	 * @return The ID of the new role.
	 */
	public static Integer createRoleForAssigningPoliciesToComputers(String apiVersion) throws ApiException {

		// Create the Role object
		Role runReportsRole = new Role();
		runReportsRole.setName("Computer Status and Properties");

		// No need for access to policies
		runReportsRole.setAllPolicies(Boolean.FALSE);

		// Add rights to edit computer properties
		ComputerRights computerRights = new ComputerRights();
		computerRights.setCanEditComputerProperties(Boolean.FALSE);

		PlatformRights platformRights = new PlatformRights();
		platformRights.setComputerRights(computerRights);

		Rights rights = new Rights();
		rights.setPlatformRights(platformRights);

		// Add rights to the role
		runReportsRole.setRights(rights);

		// Create the role on Deep Security Manager
		AdministratorRolesApi adminRolesApi = new AdministratorRolesApi();
		runReportsRole = adminRolesApi.createAdministratorRole(runReportsRole, apiVersion);

		return runReportsRole.getID();
	}
}
