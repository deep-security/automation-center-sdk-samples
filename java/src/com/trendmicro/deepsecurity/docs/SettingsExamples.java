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
		String settingName = "firewallSettingNetworkEngineMode";
		Boolean overrides = Boolean.FALSE;
		SettingValue networkEngineModeValue = policiesApi.describePolicySetting(policyID, settingName, overrides, apiVersion);

		return networkEngineModeValue.getValue();
	}

	/**
	 * Sets the value of the Network Engine Mode setting for a policy.
	 * 
	 * @param policyID The ID of the policy to modify.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when setting the policy settings on Deep Security Manager.
	 * @return The new value for the setting.
	 */
	public static SettingValue setNetworkEngineModeToInline(Integer policyID, String apiVersion) throws ApiException {
		String settingName = "firewallSettingNetworkEngineMode";
		
		// Set the value to either Inline or Tap
		SettingValue networkEngineModeValue = new SettingValue();
		networkEngineModeValue.setValue("Inline");

		// Change the setting on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicySetting(policyID, settingName, networkEngineModeValue, Boolean.FALSE, apiVersion);
	}
	
	/**
	 * Configures Firewall to operate in fail open or fail closed mode for a policy. Demonstrates how to configure multiple policy settings.
	 * 
	 * @param failOpen Indicates whether to enable fail open or fail closed mode. Set to true for fail open.
	 * @param policyID The ID of the policy to modify.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when setting the policy settings on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy setFirewallFailOpenBehavior (boolean failOpen, Integer policyID, String apiVersion) throws ApiException {
		final String FAIL_OPEN = "Fail open";
		final String FAIL_CLOSED = "Fail closed";
		
		// Create the SettingValue objects
		SettingValue failureResponseEngineSystem = new SettingValue();
		SettingValue failureResponsePacketSanityCheck = new SettingValue();
		
		// Set the values
		if (failOpen) {
			failureResponseEngineSystem.setValue(FAIL_OPEN);
			failureResponsePacketSanityCheck.setValue(FAIL_OPEN);
		} else {
			failureResponseEngineSystem.setValue(FAIL_CLOSED);
			failureResponsePacketSanityCheck.setValue(FAIL_CLOSED);
		}
		
		// Set the setting values and add to a policy
		PolicySettings policySettings = new PolicySettings();
		policySettings.setFirewallSettingFailureResponseEngineSystem(failureResponseEngineSystem);
		policySettings.setFirewallSettingFailureResponsePacketSanityCheck(failureResponsePacketSanityCheck);
		
		Policy policy = new Policy();
		policy.setPolicySettings(policySettings);
		
		// Change the setting on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyID, policy, Boolean.FALSE, apiVersion);
	}
}
