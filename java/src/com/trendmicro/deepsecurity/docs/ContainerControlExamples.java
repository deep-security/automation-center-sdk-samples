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
import com.trendmicro.deepsecurity.model.ContainerControlPolicyExtension;
import com.trendmicro.deepsecurity.model.ContainerControlVulnerabilityThreshold;
import com.trendmicro.deepsecurity.model.Policy;

public class ContainerControlExamples {
	/*
	 * Turns on the Container Control module for a policy.
	 * @param policyId The ID of the policy to modify.
	 * @param dsmClient The ApiClient for the Deep Security Manager.
	 */
	public static Policy configureContainerControl(Integer policyId, String apiVersion) throws ApiException{
		//Get the policy to modify
		PoliciesApi policiesApi = new PoliciesApi();

		//Turn on Container Control
		ContainerControlPolicyExtension containerControlPolicyExtension = new ContainerControlPolicyExtension();
		containerControlPolicyExtension.state(ContainerControlPolicyExtension.StateEnum.ON);

		// Configure Action for privileged container
		containerControlPolicyExtension.privilegedContainerAction(ContainerControlPolicyExtension.PrivilegedContainerActionEnum.DETECT);

		// Configure Action for unscanned images
		containerControlPolicyExtension.unscannedImagesAction(ContainerControlPolicyExtension.UnscannedImagesActionEnum.ALLOW);

		// Configure Action for images with malware detected
		containerControlPolicyExtension.malwareDetectedAction(ContainerControlPolicyExtension.MalwareDetectedActionEnum.BLOCK);

		// Adjust the threshold of vulnerabilities and configure action for the images that exceed vulnerability threshold
		ContainerControlVulnerabilityThreshold containerControlVulnerabilityThreshold = new ContainerControlVulnerabilityThreshold();
		containerControlVulnerabilityThreshold.defcon1Count(0);
		containerControlVulnerabilityThreshold.criticalCount(0);
		containerControlVulnerabilityThreshold.highCount(0);
		containerControlVulnerabilityThreshold.mediumCount(10);
		containerControlVulnerabilityThreshold.lowCount(-1);
		containerControlVulnerabilityThreshold.negligibleCount(-1);
		containerControlVulnerabilityThreshold.unknownCount(-1);
		containerControlPolicyExtension.vulnerabilityThreshold(containerControlVulnerabilityThreshold);
		containerControlPolicyExtension.vulnerabilityExceedThresholdAction(ContainerControlPolicyExtension.VulnerabilityExceedThresholdActionEnum.BLOCK);

		//Update the policy
		Policy updatePolicy = new Policy();
		updatePolicy.setContainerControl(containerControlPolicyExtension);

		//Update the policy on Deep Security Manager
		return policiesApi.modifyPolicy(policyId, updatePolicy, false, apiVersion);
	}
}
