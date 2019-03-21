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
import com.trendmicro.deepsecurity.api.FirewallRulesApi;
import com.trendmicro.deepsecurity.auth.ApiKeyAuth;
import com.trendmicro.deepsecurity.model.FirewallRule;
import com.trendmicro.deepsecurity.model.FirewallRules;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchFilter;

public class FirstStepsPostExample {
	/**
	 * Searches for Firewall rules that contain 'DHCP' in the name.
	 */
	public static void main(String[] args) {

		// Create the client
		ApiClient dsmClient = Configuration.getDefaultApiClient();
		dsmClient.setBasePath("https://192.168.60.128:4119/api");
		ApiKeyAuth defaultAuthentication = (ApiKeyAuth)dsmClient.getAuthentication("DefaultAuthentication");
		defaultAuthentication.setApiKey("3:fkZjcAuvj9ZWhdXgVvFl4Q3DymDZTKHOE3EDDqYPwdg=");

		// Create the search criteria
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setFieldName("name");
		searchCriteria.setStringValue("%DHCP%");
		searchCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);
		searchCriteria.setStringWildcards(Boolean.FALSE);

		// Create the search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(searchCriteria);

		// Use FirewallRulesApi to search
		FirewallRulesApi fwRulesApi = new FirewallRulesApi();
		try {
			FirewallRules fwrules = fwRulesApi.searchFirewallRules(searchFilter, "v1");
			for (FirewallRule fwrule : fwrules.getFirewallRules()) {
				System.out.println(fwrule.getName());
			}
		} catch (ApiException e) {
			e.printStackTrace();
		}
	}
}
