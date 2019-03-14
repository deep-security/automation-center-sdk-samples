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
import com.trendmicro.deepsecurity.api.SystemSettingsApi;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.SettingValue;
import com.trendmicro.deepsecurity.model.SystemSettings;

/**
 * Performs tasks related to deploying Deep Security Manager.
 */
public class AutomateDeploymentExamples {

	/**
	 * Configures the maximum number of active sessions allowed for users. Demonstrates how to configure system properties.
	 * 
	 * @param maxSessions The maximum number of active sessions.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the system settings on Deep Security Manager.
	 * @return The updated system settings.
	 */
	public static SystemSettings configureMaxSessions(int maxSessions, String apiVersion) throws ApiException {

		// Create the setting value
		SettingValue maxSessionsValue = new SettingValue();
		maxSessionsValue.setValue(Integer.toString(maxSessions));

		// Create a SystemSettings object and set the property
		SystemSettings systemSettings = new SystemSettings();
		systemSettings.setPlatformSettingActiveSessionsMax(maxSessionsValue);

		// Modify system settings on Deep Security Manager
		SystemSettingsApi settingsApi = new SystemSettingsApi();
		return settingsApi.modifySystemSettings(systemSettings, apiVersion);
	}

	/**
	 * Adds a computer to Deep Security Manager.
	 * 
	 * @param hostname The hostname or IP address that resolves to the computer.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the computer on Deep Security Manager.
	 * @return The ID of the new computer.
	 */
	public static Integer addComputer(String hostname, String apiVersion) throws ApiException {

		// Create the computer
		Computer computer = new Computer();
		computer.setHostName(hostname);

		// Add the computer to Deep Security Manager
		ComputersApi computersApi = new ComputersApi();
		computer = computersApi.createComputer(computer, Boolean.FALSE, apiVersion);

		return computer.getID();
	}
}
