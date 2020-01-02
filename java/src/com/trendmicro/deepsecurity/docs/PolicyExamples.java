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
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.Expand;
import com.trendmicro.deepsecurity.model.LogInspectionRule;
import com.trendmicro.deepsecurity.model.Policies;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchFilter;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.api.PolicyLogInspectionRuleDetailsApi;

/**
 * Creates and configures policies.
 */
public class PolicyExamples {
	/**
	 * Creates a policy that inherits from the Base Policy
	 * 
	 * @param policyName The name of the new policy.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching.
	 * @throws ApiException if a problem occurs when creating the policy on Deep Security Manager.
	 * @return The created Policy object.
	 */
	public static Policy createPolicy(String policyName, String apiVersion) throws ApiException {

		// Create search criteria to retrieve the Base Policy
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setFieldName("name");
		searchCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);
		searchCriteria.setStringValue("Base Policy");

		// Add the criteria to a search filter
		SearchFilter sf = new SearchFilter();
		sf.addSearchCriteriaItem(searchCriteria);

		// Perform the search
		PoliciesApi policiesApi = new PoliciesApi();
		Policies policies = policiesApi.searchPolicies(sf, Boolean.FALSE, apiVersion);

		// Create and configure policy object
		Policy policy = new Policy();
		policy.setName(policyName);
		policy.setDescription("Inherits from Base policy");
		policy.setRecommendationScanMode(Policy.RecommendationScanModeEnum.OFF);
		policy.setAutoRequiresUpdate(Policy.AutoRequiresUpdateEnum.ON);

		// Set the ID of the parent policy
		if (!policies.getPolicies().isEmpty()) {
			Integer id = policies.getPolicies().get(0).getID();
			policy.setParentID(id);

			// Create the policy
			return policiesApi.createPolicy(policy, Boolean.FALSE, apiVersion);
		}
		return null;
	}

	/**
	 * Assign a Linux server policy to a computer.
	 * 
	 * @param computerID The ID of the computer to assign the policy.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching and if a problem occurs when modifying the computer on Deep Security Manager.
	 * @return The modified Computer object.
	 */
	public static Computer assignLinuxServerPolicy(Integer computerID, String apiVersion) throws ApiException {

		// Create a search criteria to retrieve the Web Server policy
		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.setFieldName("name");
		searchCriteria.setStringTest(SearchCriteria.StringTestEnum.EQUAL);
		searchCriteria.setStringValue("%Linux Server%");

		// Add the criteria to a search filter
		SearchFilter sf = new SearchFilter();
		sf.addSearchCriteriaItem(searchCriteria);

		// Search for the policy
		PoliciesApi policiesApi = new PoliciesApi();
		Policies policies = policiesApi.searchPolicies(sf, Boolean.FALSE, apiVersion);

		if (policies.getPolicies().isEmpty())
			return null;

		// Set the policy for the computer
		Computer computer = new Computer();
		computer.setPolicyID(policies.getPolicies().get(0).getID());

		// Update on Deep Security Manager
		ComputersApi computersApi = new ComputersApi();
		Expand expand = new Expand();
		return computersApi.modifyComputer(computerID, computer, expand.list(), Boolean.FALSE, apiVersion);
	}

	/**
	 * Resets all but the Alert Minimum Severity and Recommendation Options overrides of a Log Inspection rule that is assigned to a
	 * policy.
	 * 
	 * @param policyID The ID of the policy that is assigned the rule.
	 * @param ruleID The ID of the Log Inspection rule.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the Log Inspection rule on Deep Security Manager.
	 * @return The created LogInspectionRule object.
	 */
	public static LogInspectionRule selectiveResetForLogInspectionRuleOnPolicy(Integer policyID, Integer ruleID, String apiVersion) throws ApiException {
		PolicyLogInspectionRuleDetailsApi policyLogInspectionRuleDetailsApi = new PolicyLogInspectionRuleDetailsApi();
		Boolean overrides = Boolean.TRUE;

		// Get the rule overrides
		LogInspectionRule ruleOverrides = policyLogInspectionRuleDetailsApi.describeLogInspectionRuleOnPolicy(policyID, ruleID, overrides, apiVersion);

		// Reset the rule
		policyLogInspectionRuleDetailsApi.resetLogInspectionRuleOnPolicy(policyID, ruleID, Boolean.FALSE, apiVersion);

		// Add the desired overrides to a new rule
		LogInspectionRule liRuleOverridesRestored = new LogInspectionRule();

		if (ruleOverrides.getAlertMinimumSeverity() != null) {
			liRuleOverridesRestored.setAlertMinimumSeverity(ruleOverrides.getAlertMinimumSeverity());
		}
		if (ruleOverrides.getRecommendationsMode() != null) {
			liRuleOverridesRestored.setRecommendationsMode(ruleOverrides.getRecommendationsMode());
		}
		// Modify the rule on Deep Security Manager
		return policyLogInspectionRuleDetailsApi.modifyLogInspectionRuleOnPolicy(policyID, ruleID, liRuleOverridesRestored, Boolean.FALSE, apiVersion);
	}
}
