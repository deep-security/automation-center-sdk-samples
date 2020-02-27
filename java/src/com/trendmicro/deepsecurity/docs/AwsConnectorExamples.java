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
import com.trendmicro.deepsecurity.api.AwsConnectorsApi;
import com.trendmicro.deepsecurity.model.AWSConnector;

/**
 * Examples of the AWS connector. 
 */
public class AwsConnectorExamples {

	/**
	 * Create an AWS connector using access keys.
	 * 
	 * @param displayName       The name of the AWS connector to show in Deep Security
	 * @param accessKey         AWS Access Key used to access this account.
	 * @param secretKey         AWS Secret Key used to access this account.
	 * @param apiVersion        The version of the API to use.
	 * @return                  Return the created AWS connector object.
	 * @throws ApiException     Throw an exception if a problem occurs when creating an AWS connector in Deep Security Manager.
	 */
	public static AWSConnector createAWSConnectorUsingAccessKeys(String displayName, String accessKey, String secretKey, String apiVersion)
			throws Exception {

		AwsConnectorsApi apiInstance = new AwsConnectorsApi();
		
		// Create an AWS connector object.
	 	AWSConnector AWSConnector = new AWSConnector();
		AWSConnector.setDisplayName(displayName);
		AWSConnector.setAccessKey(accessKey);
		AWSConnector.setSecretKey(secretKey);

		// Add the AWS connector to Deep Security Manager.
		AWSConnector result = apiInstance.createAWSConnector(AWSConnector, apiVersion);

		return result;
	}

	/**
	 * Create an AWS connector using a cross-account-role.
	 * 
	 * @param displayName           The name of the AWS connector to show in Deep Security
	 * @param crossAccountRoleArn   AWS Cross Account Role ARN used to access this account.
	 * @param apiVersion            The version of the API to use.
	 * @return                      Return the created AWS connector object.
	 * @throws ApiException         Throw an exception if a problem occurs when creating an AWS connector in Deep Security Manager.
	 */
	public static AWSConnector createAWSConnectorUsingCrossAccountRole(String displayName, String crossAccountRoleArn, String apiVersion)
			throws Exception {

		AwsConnectorsApi apiInstance = new AwsConnectorsApi();
		
		// Create an AWS connector object.
	 	AWSConnector AWSConnector = new AWSConnector();
		AWSConnector.setDisplayName(displayName);
		AWSConnector.setCrossAccountRoleArn(crossAccountRoleArn);

		// Add the AWS connector to Deep Security Manager.
		AWSConnector result = apiInstance.createAWSConnector(AWSConnector, apiVersion);

		return result;
	}

	/**
	 * Create an AWS connector using the manager instance role.
	 * 
	 * @param displayName       The name of the AWS connector to show in Deep Security
	 * @param apiVersion        The version of the API to use.
	 * @return                  Return the created AWS connector object.
	 * @throws ApiException     Throw an exception if a problem occurs when creating an AWS connector in Deep Security Manager.
	 */
	public static AWSConnector createAWSConnectorUsingInstanceRole(String displayName, String apiVersion)
			throws Exception {

		AwsConnectorsApi apiInstance = new AwsConnectorsApi();
		
		// Create an AWS connector object.
	 	AWSConnector AWSConnector = new AWSConnector();
		AWSConnector.setDisplayName(displayName);
		AWSConnector.setUseInstanceRole(true);

		// Add the AWS connector to Deep Security Manager.
		AWSConnector result = apiInstance.createAWSConnector(AWSConnector, apiVersion);

		return result;
	}
}
