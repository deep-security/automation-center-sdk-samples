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
import com.trendmicro.deepsecurity.model.FirewallPolicyExtension;
import com.trendmicro.deepsecurity.model.PolicySettings;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures the Firewall module.
 */
public class FirewallExamples {
	/**
	 * Modifies a policy to set the Firewall state to ON and enable reconnaissance scan.
	 * 
	 * @param policyId The ID of the policy to modify.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy modifyFirewallPolicy(Integer policyId, String apiVersion) throws ApiException {

		// Turn on Firewall
		FirewallPolicyExtension firewallPolicyExtension = new FirewallPolicyExtension();
		firewallPolicyExtension.setState(FirewallPolicyExtension.StateEnum.ON);

		// Add to the policy
		Policy policy = new Policy();
		policy.setFirewall(firewallPolicyExtension);

		// Turn on Reconnaissance Scan
		PolicySettings policySettings = new PolicySettings();
		SettingValue settingValue = new SettingValue();
		settingValue.setValue("true");
		policySettings.setFirewallSettingReconnaissanceEnabled(settingValue);

		// Add to the policy
		policy.setPolicySettings(policySettings);

		// Update the policy on Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion);
	}
}
