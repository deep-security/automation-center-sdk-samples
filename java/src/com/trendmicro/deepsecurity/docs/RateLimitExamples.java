/*
 * Copyright 2019 Trend Micro. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required
 * by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package com.trendmicro.deepsecurity.docs;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.model.Computer;

public class RateLimitExamples {

	/**
	 * Sets the policy for a number of computers. On each call to Deep Security Manager, checks whether the API rate limits are
	 * exceeded and if so retries the call.
	 * 
	 * @param computerIDs A list of computer IDs.
	 * @param policyID The ID of the policy to assign to the computers.
	 * @param apiVersion The API version to use.
	 * @return A list of computer IDs that were assigned the policy.
	 * @throws ApiException When a problem occurs when assigning a policy that is not due to rate limits.
	 * @throws InterruptedException When a problem occurs when thread execution is paused.
	 */
	public static List<Integer> setComputerPolicyCheckRateLimit(List<Integer> computerIDs, Integer policyID, String apiVersion) throws ApiException, InterruptedException {
		List<Integer> modifiedComputerIDs = new ArrayList<>();

		ComputersApi computersApi = new ComputersApi();

		int retries = 0; // Count the number of retries
		int maxRetries = 10; // Maximum number of retries to attempt before aborting

		while (modifiedComputerIDs.size() < computerIDs.size()) {

			// Create a computer and set the policy ID.
			Computer requestComputer = new Computer();
			requestComputer.setPolicyID(policyID);

			// Modify the computer on Deep Security Manager
			try {

				// Index of computer in ComputerIDs to modify in this iteration
				int i = modifiedComputerIDs.size();

				Computer responseComputer = computersApi.modifyComputer(computerIDs.get(i), requestComputer, Boolean.FALSE, apiVersion);
				modifiedComputerIDs.add(responseComputer.getID());
				retries = 0;
			} catch (ApiException e) {

				// Check for rate limit error -- calculate sleep time and sleep
				if (e.getCode() == 429 && retries <= maxRetries) {
					retries += 1;
					Double exp_backoff = Double.valueOf(Math.pow(2, retries + 3));
					System.out.println(String.format("API rate limit exceeded. Retry in %s ms.", Integer.valueOf(exp_backoff.intValue())));
					TimeUnit.MILLISECONDS.sleep(exp_backoff.intValue());
				}

				// Throw exception if not due to rate limiting, or max retries is exceeded
				else
					throw (e);
			}
		}
		return modifiedComputerIDs;
	}
}
