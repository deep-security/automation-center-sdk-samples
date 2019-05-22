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
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.ComputerSettings;
import com.trendmicro.deepsecurity.model.Expand;
import com.trendmicro.deepsecurity.model.SettingValue;

/**
 * Configures policy overrides on computers.
 */
public class ComputerOverrideExamples {
	/**
	 * Overrides a computer to enable Firewall reconnaissance scan.
	 * 
	 * @param computerId The ID of the computer to override.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the computer on Deep Security Manager.
	 * @return A Computer object that contains only overrides.
	 */
	public static Computer overrideReconnaissanceScan(Integer computerId, String apiVersion) throws ApiException {

		// Turn on Reconnaissance Scan
		ComputerSettings computerSettings = new ComputerSettings();
		SettingValue settingValue = new SettingValue();
		settingValue.setValue("true");
		computerSettings.setFirewallSettingReconnaissanceEnabled(settingValue);

		// Add to a computer object
		Computer computer = new Computer();
		computer.setComputerSettings(computerSettings);

		// Update on Deep Security Manager
		ComputersApi computersApi = new ComputersApi();
		return computersApi.modifyComputer(computerId, computer, Boolean.TRUE, apiVersion);
	}

	/**
	 * Obtains a Computer object that contains only overrides.
	 * 
	 * @param comptuerId The ID of the computer.
	 * @param expand The list of computer properties to include in the returned Computer object. 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when getting the computer from Deep Security Manager.
	 * @return The Computer object with overrides.
	 */
	public static Computer getComputerOverrides(Integer computerId, Expand expand, String apiVersion) throws ApiException {
		ComputersApi computersApi = new ComputersApi();

		// Set the overrides parameter to true
		return computersApi.describeComputer(computerId, expand.list(), Boolean.TRUE, apiVersion);
	}
}
