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
import com.trendmicro.deepsecurity.model.PolicySettings;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures various policy settings.
 */
public class SettingsExamples {

	/**
	 * Gets the value of the Network Engine Mode setting for a policy.
	 * 
	 * @param policyID The ID of the policy.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when retrieving the policy settings.
	 * @return A String that contains the setting value.
	 */
	public static String getNetworkEngineMode(Integer policyID, String apiVersion) throws ApiException {
		PoliciesApi policiesApi = new PoliciesApi();
		Policy policy = policiesApi.describePolicy(policyID, Boolean.FALSE, apiVersion);
		PolicySettings policySettings = policy.getPolicySettings();
		SettingValue networkEngineModeValue = policySettings.getFirewallSettingNetworkEngineMode();

		return networkEngineModeValue.getValue();
	}

	/**
	 * Sets the value of the Network Engine Mode setting for a policy.
	 * 
	 * @param policyID The ID of the policy to modify.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when setting the policy settings on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy setNetworkEngineModeToInline(Integer policyID, String apiVersion) throws ApiException {

		// Set the value to either Inline or Tap
		SettingValue networkEngineModeValue = new SettingValue();
		networkEngineModeValue.setValue("Inline");

		PolicySettings policySettings = new PolicySettings();
		policySettings.setFirewallSettingNetworkEngineMode(networkEngineModeValue);

		Policy policy = new Policy();
		policy.setPolicySettings(policySettings);

		// Change the setting on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyID, policy, Boolean.FALSE, apiVersion);
	}
}
