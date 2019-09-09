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

import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.IntrusionPreventionRulesApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.model.IntrusionPreventionRules;
import com.trendmicro.deepsecurity.model.Policies;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.Computers;
import com.trendmicro.deepsecurity.model.Expand;
import com.trendmicro.deepsecurity.model.SearchFilter;

/**
 * Searches various resources.
 */
public class SearchExamples {

	/**
	 * Searches for a policy by name
	 * 
	 * @param name The policy name to search.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @Return The found Policy object, or null if no policy is found.
	 */
	public static Policy searchPoliciesByName(String name, String apiVersion) throws ApiException {

		// Create a search criteria
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setFieldName("name");
		searchCriteria.setStringValue(name);
		searchCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);

		// Create and configure a search filter
		SearchFilter searchFilter = new SearchFilter();

		// Return only one policy
		searchFilter.setMaxItems(Integer.valueOf(1));
		searchFilter.addSearchCriteriaItem(searchCriteria);

		// Search
		PoliciesApi policiesApi = new PoliciesApi();
		Policies policies = policiesApi.searchPolicies(searchFilter, Boolean.FALSE, apiVersion);

		if (!policies.getPolicies().isEmpty()) {
			return policies.getPolicies().get(0);
		}
		return null;
	}

	/**
	 * Searches for Intrusion Prevention rules that have been updated within a specific number of days.
	 * 
	 * @param days The number of days.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @return A list of found rules.
	 */
	public static IntrusionPreventionRules searchUpdatedIntrusionPreventionRules(int days, String apiVersion) throws ApiException {

		// Dates to search
		Long last = Long.valueOf(Calendar.getInstance().getTimeInMillis());
		Long first = Long.valueOf(last.intValue() - TimeUnit.DAYS.toMillis(days));

		// Create a search criteria
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setFieldName("lastUpdated");
		searchCriteria.setFirstDateValue(first);
		searchCriteria.setLastDateValue(last);
		searchCriteria.setFirstDateInclusive(Boolean.TRUE);
		searchCriteria.setLastDateInclusive(Boolean.TRUE);

		// Create the search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(searchCriteria);

		// Perform the search
		IntrusionPreventionRulesApi ipRulesApi = new IntrusionPreventionRulesApi();
		return ipRulesApi.searchIntrusionPreventionRules(searchFilter, apiVersion);
	}

	/**
	 * Searches computers and returns results in pages. For each page, prints the names of the computers.
	 * 
	 * @param pageSize The number of computers to include in each page.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 */
	public static void pagedSearchComputers(Integer pageSize, String apiVersion) throws ApiException {

		// Create a search criteria
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setIdValue(Long.valueOf(0L));
		searchCriteria.setIdTest(SearchCriteria.IdTestEnum.GREATER_THAN);

		// Set up the search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.setMaxItems(pageSize);
		searchFilter.addSearchCriteriaItem(searchCriteria);
		
		// Include the minimum information in returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.NONE);

		ComputersApi computersApi = new ComputersApi();

		// Use in loop exit expression
		int found;
		do {
			// Find a page of computers and save the number found
			Computers computers = computersApi.searchComputers(searchFilter, expand.list(), Boolean.FALSE, apiVersion);

			found = computers.getComputers().size();
			if (found > 0) {

				// Print some page details
				System.out.println("Computers in page:");
				for (Computer computer : computers.getComputers()) {
					System.out.println(computer.getHostName());
				}

				// Get the highest ID found and adjust the search filter for the next search
				Integer lastID = computers.getComputers().get(computers.getComputers().size() - 1).getID();
				searchCriteria.setIdValue(Long.valueOf(lastID.toString()));
			}
		} while (found > 0); // Exit loop when no computers are found
	}

	/**
	 * Search for computers that are assigned to a specific policy and relay list.
	 * 
	 * @param relayListID The ID of the relay list.
	 * @param policyID The ID of the policy.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @returns A Computers object that contains matching computers.
	 */
	public static Computers getComputersWithPolicyAndRelayList(Long relayListID, Long policyID, String apiVersion) throws ApiException {

		// Search criteria for platform
		SearchCriteria relayCrit = new SearchCriteria();
		relayCrit.setFieldName("relayListID");
		relayCrit.setNumericValue(relayListID);
		relayCrit.setNumericTest(SearchCriteria.NumericTestEnum.EQUAL);

		// Search criteria for policy ID
		SearchCriteria policyCrit = new SearchCriteria();
		policyCrit.setFieldName("policyID");
		policyCrit.setNumericValue(policyID);
		policyCrit.setNumericTest(SearchCriteria.NumericTestEnum.EQUAL);

		// Search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(relayCrit);
		searchFilter.addSearchCriteriaItem(policyCrit);
		
		// Include the minimum information in returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.NONE);

		// Perform the search
		ComputersApi computersApi = new ComputersApi();
		return computersApi.searchComputers(searchFilter, expand.list(), Boolean.FALSE, apiVersion);
	}
	
	/**
	 * Search for protected EC2 instances that belong to a specific AWS account.
	 * 
	 * @param accountID The ID of the AWS account.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @returns A Computers object that contains matching computers.
	 */
	public static Computers searchComputersByAwsAccount(String accountID, String apiVersion) throws ApiException {
		// Search criteria for the account ID
		SearchCriteria computerCriteria = new SearchCriteria();
		computerCriteria.setFieldName("ec2VirtualMachineSummary/accountID");
		computerCriteria.setStringValue(accountID);
		computerCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);

		// Search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(computerCriteria);
		
		// Include only ec2VirtualMachineSummary in the returned computer objects 
		Expand expand = new Expand();
		expand.add(Expand.OptionsEnum.EC2_VIRTUAL_MACHINE_SUMMARY);
		
		ComputersApi computersApi = new ComputersApi();
		return computersApi.searchComputers(searchFilter, expand.list(), Boolean.FALSE, apiVersion);
	}
	/**
	 * Search for computers that have not had their policy updated.
	 * Demonstrates a search for a null value.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @returns A Computers object that contains matching computers.
	 */
	public static Computers searchComputersNotUpdated(String apiVersion) throws ApiException {
		
		//Search criteria for the lastSendPolicySuccess field
		SearchCriteria computerCriteria = new SearchCriteria();
		computerCriteria.setFieldName("lastSendPolicySuccess");
		computerCriteria.setNullTest(Boolean.TRUE);

		// Search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(computerCriteria);

		// Include minimal information in the returned computer objects 
		Expand expand = new Expand();
		expand.add(Expand.OptionsEnum.NONE);

		ComputersApi computersApi = new ComputersApi();
		return computersApi.searchComputers(searchFilter, expand.list(), Boolean.FALSE, apiVersion);
	}
}
