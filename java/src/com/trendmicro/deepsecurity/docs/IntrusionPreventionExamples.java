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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.Computers;
import com.trendmicro.deepsecurity.model.IntrusionPreventionComputerExtension;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.PolicySettings;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures the Intrusion Prevention module.
 */
public class IntrusionPreventionExamples {
	/**
	 * Turns on the automatic application of recommendation scans for Intrusion Prevention in a policy.
	 * 
	 * @param policyId The ID of the policy to modify.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy modifyIntrusionPreventionPolicy(Integer policyId, String apiVersion) throws ApiException {

		// Create a setting object and turn on automatic application of recommendation
		// scans
		PolicySettings policySettings = new PolicySettings();
		SettingValue settingValue = new SettingValue();
		settingValue.setValue("Yes");
		policySettings.setIntrusionPreventionSettingAutoApplyRecommendationsEnabled(settingValue);

		// Add to a policy
		Policy policy = new Policy();
		policy.setPolicySettings(policySettings);

		// Update the policy on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion);
	}

	/**
	 * Compiles a list of intrusion prevention rules that are applied to each computer.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when obtaining the list of computers.
	 * @return A Map that uses computer IDs as keys and a list of rules (or null if no rules) as values.
	 */
	public static Map<Integer, List<Integer>> getIntrusionPreventionRules(String apiVersion) throws ApiException {
		Map<Integer, List<Integer>> computerRules = new HashMap<>();
		ComputersApi computersApi = new ComputersApi();

		// Get all computer IDs
		Computers computers = computersApi.listComputers(Boolean.FALSE, apiVersion);

		// For each computer, get the IDs for the assigned rules
		for (Computer computer : computers.getComputers()) {
			IntrusionPreventionComputerExtension ipce = computer.getIntrusionPrevention();
			computerRules.put(computer.getID(), ipce.getRuleIDs());
		}
		return computerRules;
	}
}
