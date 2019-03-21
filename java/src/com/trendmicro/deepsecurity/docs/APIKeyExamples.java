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

import java.util.Date;
import java.util.concurrent.TimeUnit;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.ApiKeysApi;
import com.trendmicro.deepsecurity.model.ApiKey;

/**
 * Creates and configures API keys.
 */
public class APIKeyExamples {
	/**
	 * Creates an API key for auditing that expires in 2 weeks.
	 * 
	 * @param keyName The name for the API key.
	 * @param auditRoleID The ID of the auditor role.
	 * @param apiVersion The API version to use.
	 * @throws ApiException if a problem occurs when creating the API key on Deep Security Manager.
	 * @return The new API key.
	 */
	public static ApiKey createAuditKey(String keyName, Integer auditRoleID, String apiVersion) throws ApiException {

		// Create a key object
		ApiKey key = new ApiKey();
		key.setKeyName(keyName);
		key.setDescription("Read-only access");
		key.setRoleID(auditRoleID);
		key.setLocale(ApiKey.LocaleEnum.EN_US);
		key.setTimeZone("Asia/Tokyo");
		// Expires 2 weeks from now
		key.setExpiryDate(new Long(new Date().getTime() + TimeUnit.DAYS.toMillis(14)));

		// Create the key on Deep Security Manager
		ApiKeysApi apiKeysApi = new ApiKeysApi();
		return apiKeysApi.createApiKey(key, apiVersion);
	}

	/**
	 * Resets the secret key for an API key.
	 * 
	 * @param key The API key.
	 * @param apiVersion The API version to use.
	 * @throws ApiException if a problem occurs when resetting the secret key on Deep Security Manager.
	 * @return The modified API key.
	 */
	public static ApiKey resetKeySecret(ApiKey key, String apiVersion) throws ApiException {
		ApiKeysApi apiKeysApi = new ApiKeysApi();
		return apiKeysApi.replaceApiSecretKey(key.getID(), apiVersion);
	}

	/**
	 * Changes the user role with which an API key is associated.
	 * 
	 * @param key The API key to modify.
	 * @param roleID The ID of the role to associate with the API key.
	 * @param apiVersion The API version to use.
	 * @throws ApiException if a problem occurs when modifying the API key on Deep Security Manager.
	 * @return The modified API key.
	 */
	public static ApiKey modifyKeyRole(ApiKey key, Integer roleID, String apiVersion) throws ApiException {

		// Create Key object that uses the role
		ApiKey keyWithRole = new ApiKey();
		keyWithRole.setRoleID(roleID);

		// Update the key on Deep Security Manager
		ApiKeysApi apiKeysApi = new ApiKeysApi();
		return apiKeysApi.modifyApiKey(key.getID(), keyWithRole, apiVersion);
	}
}