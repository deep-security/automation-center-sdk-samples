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
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.LogInspectionPolicyExtension;
import com.trendmicro.deepsecurity.model.LogInspectionPolicyExtension.StateEnum;

/**
 * Configures the Log Inspection module.
 */
public class LogInspectionExamples {
	/**
	 * Turns on Log Inspection and adds a Log Inspection rule for a policy.
	 * 
	 * @param policyId The ID of the policy to modify.
	 * @param liRule The rule ID to add.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The ID of the modified policy.
	 */
	public static Integer addLogInspectionRule(Integer policyId, Integer liRule, String apiVersion) throws ApiException {
		
		// Turn on Log Inspection
		LogInspectionPolicyExtension logInspectionPolicyExtension = new LogInspectionPolicyExtension();
		logInspectionPolicyExtension.setState(StateEnum.ON);

		// Add the rule ID
		logInspectionPolicyExtension.addRuleIDsItem(liRule);
		
		// Add to a policy
		Policy policy = new Policy();
		policy.setLogInspection(logInspectionPolicyExtension);

		// Update the policy on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion).getID();
	}
}
