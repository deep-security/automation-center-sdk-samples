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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.trendmicro.deepsecurity.ApiClient;
import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.Configuration;
import com.trendmicro.deepsecurity.api.ApiKeysApi;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.api.TenantsApi;
import com.trendmicro.deepsecurity.auth.ApiKeyAuth;
import com.trendmicro.deepsecurity.model.Administrator;
import com.trendmicro.deepsecurity.model.ApiKey;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.Computers;
import com.trendmicro.deepsecurity.model.IntrusionPreventionComputerExtension;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchFilter;
import com.trendmicro.deepsecurity.model.Tenant;
import com.trendmicro.deepsecurity.model.Tenant.ModulesVisibleEnum;
import com.trendmicro.deepsecurity.model.Tenants;

/**
 * Creates and configures tenants.
 */
public class TenantExamples {

	/**
	 * Creates a tenant on the primary Deep Security Manager
	 * 
	 * @param accountName The name of the tenant account.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the tenant on Deep Security Manager.
	 * @return The new tenant.
	 */
	public static Tenant createTenant(String accountName, String apiVersion) throws ApiException {

		// Create and configure a Tenant object
		Tenant tenant = new Tenant();

		// Set module visibility
		List<ModulesVisibleEnum> modules = new ArrayList<>();
		modules.add(ModulesVisibleEnum.ANTI_MALWARE);
		modules.add(ModulesVisibleEnum.FIREWALL);
		modules.add(ModulesVisibleEnum.INTRUSION_PREVENTION);

		// Administrator account
		Administrator admin = new Administrator();
		admin.setUsername("MasterAdmin");
		admin.setPassword("P@55word");
		admin.setEmailAddress("bad@email.com");

		tenant.setName(accountName);
		tenant.setLocale(Tenant.LocaleEnum.EN_US);
		tenant.setDescription("Test tenant.");
		tenant.setAdministrator(admin);
		tenant.setModulesVisible(modules);

		// Add the tenant to the manager
		TenantsApi tenantsApi = new TenantsApi();
		return tenantsApi.createTenant(tenant, Boolean.TRUE, Boolean.FALSE, Boolean.TRUE, apiVersion);
	}

	/**
	 * Retrieves the state of the Intrusion Prevention module for a tenant's computers
	 * 
	 * @param tenantID The ID of the tenant.
	 * @param roleID The ID of the role to use for the tenant's API key
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when deleting and creating API keys, and if a problem occurs when obtaining the list of computers.
	 * @return A Map that uses the computer ID as the key and the intrusion prevention state as the value.
	 */
	public static Map<Integer, IntrusionPreventionComputerExtension.StateEnum> getIPStatesForTenant(Integer tenantID, Integer roleID, String apiVersion) throws ApiException {

		Map<Integer, IntrusionPreventionComputerExtension.StateEnum> computerIPStates = new HashMap<>();

		// Create the key object
		ApiKey key = new ApiKey();
		key.setKeyName("Temporary Key");
		key.setRoleID(roleID);
		key.setLocale(ApiKey.LocaleEnum.EN_US);
		key.setTimeZone("Asia/Tokyo");

		// Add the key to Deep Security Manager
		TenantsApi tenantsApi = new TenantsApi();
		key = tenantsApi.generateTenantApiSecretKey(tenantID, key, apiVersion);

		// Configure an APIClient using the new key's secret
		ApiClient tenantClient = Configuration.getDefaultApiClient();
		ApiKeyAuth DefaultAuthentication = (ApiKeyAuth)tenantClient.getAuthentication("DefaultAuthentication");
		DefaultAuthentication.setApiKey(key.getSecretKey());

		// Get the computers and find the states
		ComputersApi tnComputerApi = new ComputersApi(tenantClient);
		Computers computers;
		computers = tnComputerApi.listComputers(Boolean.FALSE, apiVersion);

		for (Computer computer : computers.getComputers()) {
			computerIPStates.put(computer.getID(), computer.getIntrusionPrevention().getState());
		}

		// Delete the tenant key
		ApiKeysApi tnApiKeysApi = new ApiKeysApi(tenantClient);
		tnApiKeysApi.deleteApiKey(key.getID(), apiVersion);

		return computerIPStates;
	}

	/**
	 * Retrieves the Intrusion Prevention rules that are applied to all computers of all tenants.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching, if a problem occurs when deleting and creating API keys, and if a problem occurs when listing computers.
	 * @return A Map object that uses the tenant ID as the key, and a Map of rules that are applied to the computers.
	 */
	public static Map<Integer, Map<Integer, ArrayList<Integer>>> getTenantRules(String apiVersion) throws ApiException, IOException {

		// Key is tenant ID. Value is a list of computer rule IDs
		Map<Integer, Map<Integer, ArrayList<Integer>>> tenantMap = new HashMap<>();

		// Key is computer ID. Value is a list of rule IDs
		Map<Integer, ArrayList<Integer>> computerRules = new HashMap<>();

		// Obtain connection properties from local properties file
		Properties properties = new Properties();
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		try (InputStream input = classLoader.getResourceAsStream("com/trendmicro/deepsecurity/docs/Resources/example.properties")) {
			properties.load(input);

			String primarySecretKey = properties.getProperty("secretkey");
			String primaryURL = properties.getProperty("url");

			// Configure the ApiClient
			ApiClient apiClient = Configuration.getDefaultApiClient();
			apiClient.setBasePath(primaryURL);
			ApiKeyAuth defaultAuthentication = (ApiKeyAuth)apiClient.getAuthentication("DefaultAuthentication");
			defaultAuthentication.setApiKey(primarySecretKey);

			// Search for Active tenants
			SearchCriteria searchCriteria = new SearchCriteria();
			searchCriteria.setFieldName("tenantState");
			searchCriteria.setChoiceValue("active");
			searchCriteria.setChoiceTest(SearchCriteria.ChoiceTestEnum.EQUAL);

			// Search filter
			SearchFilter searchFilter = new SearchFilter();
			searchFilter.setMaxItems(Integer.valueOf(1));
			searchFilter.addSearchCriteriaItem(searchCriteria);

			TenantsApi tenantsApi = new TenantsApi();
			Tenants tenants = tenantsApi.searchTenants(searchFilter, apiVersion);

			// Iterate the tenants
			for (Tenant tenant : tenants.getTenants()) {
				// For each tenant create an api key
				ApiKey tenantKey = new ApiKey();
				tenantKey.setKeyName("Temporary Key");
				tenantKey.setRoleID(Integer.valueOf(1));
				tenantKey.setLocale(ApiKey.LocaleEnum.EN_US);
				tenantKey.setTimeZone("Asia/Tokyo");
				// Add the key to Deep Security Manager
				tenantKey = tenantsApi.generateTenantApiSecretKey(tenant.getID(), tenantKey, apiVersion);

				// Configure the ApiClient to use the tenant's secret key
				defaultAuthentication.setApiKey(tenantKey.getSecretKey());

				// Create a ComputersApi object for the tenant
				ComputersApi tnComputersApi = new ComputersApi();

				// Iterate over the tenant computers
				Computers tenantComputers = tnComputersApi.listComputers(Boolean.FALSE, apiVersion);
				for (Computer tenantComputer : tenantComputers.getComputers()) {
					IntrusionPreventionComputerExtension intrusionPeventionComputerExtension = tenantComputer.getIntrusionPrevention();
					computerRules.put(tenantComputer.getID(), (ArrayList<Integer>)intrusionPeventionComputerExtension.getRuleIDs());
				}
				tenantMap.put(tenant.getID(), computerRules);

				// Delete the tenant key
				ApiKeysApi tnApiKeysApi = new ApiKeysApi();
				tnApiKeysApi.deleteApiKey(tenantKey.getID(), apiVersion);
				tenantKey = null;

				// Configure the ApiClient to use the primary tenant's Secret Key
				defaultAuthentication.setApiKey(primarySecretKey);
			}
			return tenantMap;
		}
	}

	/**
	 * Adds a policy to a tenant
	 * 
	 * @param policy The Policy to add to the tenant.
	 * @param tenantID The ID of the tenant.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when deleting and creating API keys and if a problem occurs when creating the policy on Deep Security Manager.
	 * @return The created policy.
	 */
	public static Policy addTenantPolicy(Policy policy, Integer tenantID, String apiVersion) throws ApiException {

		// Create an API key for the tenant
		TenantsApi tenantsApi = new TenantsApi();
		ApiKey tenantKey = new ApiKey();
		tenantKey.setKeyName("Tenant Key");
		tenantKey.setRoleID(Integer.valueOf(1));
		tenantKey = tenantsApi.generateTenantApiSecretKey(tenantID, tenantKey, apiVersion);

		// Create an ApiClient object for the tenant
		ApiClient tenantClient = Configuration.getDefaultApiClient();
		tenantClient.setBasePath("https://localhost:4119/api");
		ApiKeyAuth defaultAuthentication = (ApiKeyAuth)tenantClient.getAuthentication("DefaultAuthentication");
		defaultAuthentication.setApiKey(tenantKey.getSecretKey());

		// Add the policy
		PoliciesApi tnPoliciesApi = new PoliciesApi(tenantClient);
		policy = tnPoliciesApi.createPolicy(policy, Boolean.FALSE, apiVersion);

		// Delete the tenant key
		ApiKeysApi tnApiKeysApi = new ApiKeysApi(tenantClient);
		tnApiKeysApi.deleteApiKey(tenantKey.getID(), apiVersion);

		return policy;
	}
}
