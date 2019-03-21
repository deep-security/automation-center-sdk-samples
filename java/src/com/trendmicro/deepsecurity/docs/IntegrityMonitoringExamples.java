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

/**
 * Configures the Integrity Monitoring module.
 */
public class IntegrityMonitoringExamples {
	/**
	 * Adds Integrity Monitoring rules to a policy.
	 * 
	 * @param policyID The ID of the policy to modify.
	 * @param ruleIds A List of rule IDs to add.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy configureIntegrityMonitoring(Integer policyId, List<Integer> ruleIds, String apiVersion) throws ApiException {

		// Add the rule IDs to a policy
		IntegrityMonitoringPolicyExtension integrityMonitoringPolicyExtension = new IntegrityMonitoringPolicyExtension();
		for (Integer ruleId : ruleIds) {
			integrityMonitoringPolicyExtension.addRuleIDsItem(ruleId);
		}
		Policy policy = new Policy();
		policy.setIntegrityMonitoring(integrityMonitoringPolicyExtension);

		// Update the policy on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion);
	}
}
