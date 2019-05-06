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

import java.util.List;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.IntegrityMonitoringPolicyExtension;
import com.trendmicro.deepsecurity.model.IntegrityMonitoringPolicyExtension.StateEnum;

/**
 * Configures the Integrity Monitoring module.
 */
public class IntegrityMonitoringExamples {
	/**
	 * Turns on Integrity Monitoring and adds Integrity Monitoring rules for a policy.
	 * 
	 * @param policyID The ID of the policy to modify.
	 * @param ruleIds A List of rule IDs to add.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The ID of the modified policy.
	 */
	public static Integer configureIntegrityMonitoring(Integer policyId, List<Integer> ruleIds, String apiVersion) throws ApiException {

		// Set the state
		IntegrityMonitoringPolicyExtension integrityMonitoringPolicyExtension = new IntegrityMonitoringPolicyExtension();
		integrityMonitoringPolicyExtension.setState(StateEnum.ON);
		
		// Add the rule IDs
		integrityMonitoringPolicyExtension.setRuleIDs(ruleIds);
		
		// Add to a policy
		Policy policy = new Policy();
		policy.setIntegrityMonitoring(integrityMonitoringPolicyExtension);

		// Update the policy on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		Policy modifiedPolicy = policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion);
		
		return modifiedPolicy.getID();
	}
}
