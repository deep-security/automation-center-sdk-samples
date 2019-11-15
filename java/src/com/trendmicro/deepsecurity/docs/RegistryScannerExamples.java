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
import com.trendmicro.deepsecurity.api.RegistryScannersApi;
import com.trendmicro.deepsecurity.model.RegistryScanner;

public class RegistryScannerExamples {
	/**
	 * Adds a registry scanner to Deep Security Manager.
	 * @param apiVersion The version of the API to use.
	 * @param name The name or IP address of the registry scanner.
	 * @param url The url of the registry scanner.
	 * @param user_account The user account that can login to the registry scanner.
	 * @param user_password The password of the user.
	 * @return The ID of the registry scanner
	 * @throws ApiException When a problem occurs when creating registry scanner.
	 */
	public static Integer createRegistryScanner(String apiVersion, String name, String url, String user_account, String user_password) throws ApiException{
		//Create the registry scanner object
		RegistryScanner registryScanner = new RegistryScanner();
		registryScanner.setName(name);
		registryScanner.setUrl(url);
		registryScanner.setUsername(user_account);
		registryScanner.setPassword(user_password);

		//Add the registry scanner to Deep Security Manager
		RegistryScannersApi registryScannersApi = new RegistryScannersApi();
		try {
			registryScanner = registryScannersApi.createRegistryScanner(registryScanner, apiVersion);
		} catch (ApiException e) {
			e.printStackTrace();
		}
		return registryScanner.getID();
	}
}
