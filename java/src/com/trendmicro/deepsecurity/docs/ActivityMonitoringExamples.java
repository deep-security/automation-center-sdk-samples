/* 
 * Copyright 2020 Trend Micro.
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
import com.trendmicro.deepsecurity.model.ActivityMonitoringPolicyExtension;
import com.trendmicro.deepsecurity.model.PolicySettings;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures the Activity Monitoring module.
 */
public class ActivityMonitoringExamples {

	/**
	 * Sets the Activity Monitoring, and set the ActivityEnabled Setting for a policy.
	 * 
	 * @param policyId The ID of the policy to configure.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Integer setActivityMonitoring(Integer policyId, String apiVersion) throws ApiException {

		// Set the state, security level, and Smart Protection Server
		ActivityMonitoringPolicyExtension activityMonitoringExtension = new ActivityMonitoringPolicyExtension();
		activityMonitoringExtension.setState(ActivityMonitoringPolicyExtension.StateEnum.ON);

		SettingValue activityEnabledValue = new SettingValue();
		activityEnabledValue.setValue("On");

		PolicySettings policySettings = new PolicySettings();
		policySettings.setActivityMonitoringSettingActivityEnabled(activityEnabledValue);

		// Add to a policy object
		Policy policy = new Policy();
		policy.setActivityMonitoring(activityMonitoringExtension);
		policy.setPolicySettings(policySettings);

		// Send the policy to Deep Security Manager
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, policy, Boolean.FALSE, apiVersion).getID();
	}
}
