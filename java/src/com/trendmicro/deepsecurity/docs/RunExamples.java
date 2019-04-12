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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.ThreadLocalRandom;

import com.trendmicro.deepsecurity.ApiClient;
import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.Configuration;
import com.trendmicro.deepsecurity.auth.ApiKeyAuth;

import com.trendmicro.deepsecurity.docs.PolicyExamples;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.Computer;

/**
 * Use to run the samples that complement the Deep Security Automation Center guides.
 */
public class RunExamples {

	// Values to use for example method arguments. Edit according to your environment.
	private static String	apiVersion	= "v1";
	private static String	policyName	= "Test Policy " + ThreadLocalRandom.current().nextInt(1, 1000);	// Suffix avoids collisions
	private static Integer	computerID	= new Integer(801);

	public static void main(String[] args) {

		// Retrieve the DSM url and secret key from the properties file
		Properties properties = new Properties();
		ClassLoader loader = Thread.currentThread().getContextClassLoader();
		try (InputStream stream = loader.getResourceAsStream("com/trendmicro/deepsecurity/docs/Resources/example.properties")) {
			properties.load(stream);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Configure ApiClient
		ApiClient dsmClient = Configuration.getDefaultApiClient();
		dsmClient.setBasePath(properties.getProperty("url") + "/api");
		ApiKeyAuth defaultAuthentication = (ApiKeyAuth)dsmClient.getAuthentication("DefaultAuthentication");
		defaultAuthentication.setApiKey(properties.getProperty("secretkey"));

		// Run the policy examples
		try {
			runPolicyExamples();
		} catch (ApiException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Runs examples in the com.trendmicro.deepsecurity.docs.PolicyExample class. The policy name and computer ID values are set in
	 * global variables.
	 * 
	 * @throws ApiException if a problem occurs when creating the and if a problem occurs when assigning the policy.
	 */
	private static void runPolicyExamples() throws ApiException {
		Policy testPolicy = PolicyExamples.createPolicy(policyName, apiVersion);
		Computer computer = PolicyExamples.assignLinuxServerPolicy(computerID, apiVersion);

		System.out.println(String.format("Created policy: %d\nComputer's policy: %d", testPolicy.getID(), computer.getPolicyID()));
	}
}
