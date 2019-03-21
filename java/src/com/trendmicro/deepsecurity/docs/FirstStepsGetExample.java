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

import com.trendmicro.deepsecurity.ApiClient;
import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.Configuration;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.auth.ApiKeyAuth;
import com.trendmicro.deepsecurity.model.Policies;
import com.trendmicro.deepsecurity.model.Policy;

public class FirstStepsGetExample {
	/**
	 * Retrieves all policies and prints the names.
	 */
	public static void main(String[] args) {

		// Create the client
		ApiClient dsmClient = Configuration.getDefaultApiClient();
		dsmClient.setBasePath("https://192.168.60.128:4119/api");
		ApiKeyAuth defaultAuthentication = (ApiKeyAuth)dsmClient.getAuthentication("DefaultAuthentication");
		defaultAuthentication.setApiKey("3:/tiKl3+6ritnk4tQXipq5ufIls5nCFqoGoUcWl+imTU=");

		// Create a PoliciesApi object
		PoliciesApi policiesApi = new PoliciesApi();
		try {

			// List policies. Use version v1 of the API.
			Policies policies = policiesApi.listPolicies(Boolean.FALSE, "v1");
			for (Policy policy : policies.getPolicies()) {
				System.out.println(policy.getName());
			}
		} catch (ApiException e) {
			e.printStackTrace();
		}
	}
}
