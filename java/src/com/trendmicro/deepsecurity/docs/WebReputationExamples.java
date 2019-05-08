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
import com.trendmicro.deepsecurity.model.WebReputationPolicyExtension;
import com.trendmicro.deepsecurity.model.PolicySettings;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures the Web Reputation module.
 */
public class WebReputationExamples {

	/**
	 * Sets the Web Reputation module state to ON, sets the security level, and enables Smart Protection Server for a policy.
	 * 
	 * @param policyId The ID of the policy to configure.
	 * @param securityLevel The security level to set for Web Reputation.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Integer setSecurityLevel(Integer policyId, String securityLevel, String apiVersion) throws ApiException {

		// Set the state, security level, and Smart Protection Server
		WebReputationPolicyExtension webReputationPolicyExtension = new WebReputationPolicyExtension();
		webReputationPolicyExtension.setState(WebReputationPolicyExtension.StateEnum.ON);

		SettingValue securityLevelValue = new SettingValue();
		securityLevelValue.setValue(securityLevel);

		PolicySettings policySettings = new PolicySettings();
		policySettings.setWebReputationSettingSecurityLevel(securityLevelValue);

		SettingValue allowGlobalValue = new SettingValue();
		allowGlobalValue.setValue("true");

		policySettings.setWebReputationSettingSmartProtectionLocalServerAllowOffDomainGlobal(allowGlobalValue);

		// Add to a policy object
		Policy policy = new Policy();
		policy.setWebReputation(webReputationPolicyExtension);
		policy.setPolicySettings(policySettings);

		// Send the policy to Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion).getID();
	}
}
