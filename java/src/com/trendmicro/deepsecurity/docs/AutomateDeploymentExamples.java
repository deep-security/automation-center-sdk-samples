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
import com.trendmicro.deepsecurity.api.AgentDeploymentScriptsApi;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.SystemSettingsApi;
import com.trendmicro.deepsecurity.model.AgentDeploymentScript;
import com.trendmicro.deepsecurity.model.AgentDeploymentScript.PlatformEnum;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.SettingValue;
import com.trendmicro.deepsecurity.model.SystemSettings;

/**
 * Performs tasks related to deploying Deep Security Manager.
 */
public class AutomateDeploymentExamples {

	/**
	 * Configures the maximum number of active sessions allowed for users, and the action to take when the maximum is exceeded. 
	 * Demonstrates how to set multiple system properties.
	 * 
	 * @param maxSessions The maximum number of active sessions.
	 * @param exceedAction The action to take when a user exceeds the maximum number of sessions. Valid values are "Block new sessions" and "Expire oldest session".
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the system settings on Deep Security Manager.
	 * @return The updated system settings.
	 */
	public static SystemSettings configureMaxSessions(int maxSessions, String exceedAction, String apiVersion) throws ApiException {

		// Create the setting value for PlatformSettingActiveSessionsMax
		SettingValue maxSessionsValue = new SettingValue();
		maxSessionsValue.setValue(Integer.toString(maxSessions));

		// Create a SystemSettings object and set the property
		SystemSettings systemSettings = new SystemSettings();
		systemSettings.setPlatformSettingActiveSessionsMax(maxSessionsValue);
		
		// Repeat for platformSettingActiveSessionsMaxExceededAction
		SettingValue maxSessionsExceededAction = new SettingValue();
		maxSessionsExceededAction.setValue(exceedAction);
		systemSettings.setPlatformSettingActiveSessionsMaxExceededAction(maxSessionsExceededAction);

		// Modify system settings on Deep Security Manager
		SystemSettingsApi settingsApi = new SystemSettingsApi();
		return settingsApi.modifySystemSettings(systemSettings, apiVersion);
	}
	/**
	 * Configures whether agent-initiated activation is allowed. Demonstrates how to set a single system property.
	 * 
	 * @param allowValue Whether to allow agent-initiated activations. 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the system setting on Deep Security Manager.
	 * @return The updated system setting value.
	 */
	public static SettingValue setAllowAgentInitiatedActivation(String allowValue, String apiVersion) throws ApiException {
		String settingName = "platformSettingAgentInitiatedActivationEnabled";
		
		// Create the setting value
		SettingValue agentInitiatedActivationEnabled = new SettingValue();
		agentInitiatedActivationEnabled.setValue(allowValue);
		
		// Modify the system setting on Deep Security Manager
		SystemSettingsApi settingsApi = new SystemSettingsApi();
		return settingsApi.modifySystemSetting(settingName, agentInitiatedActivationEnabled, apiVersion);
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
	
	/**
	 * Obtains an agent deployment script from Deep Security Manager according to the provided parameter values.
	 * 
	 * @param platform A PlatformEnum that indicates the platform of the target computer.
	 * @param dsmProxyID The Integer ID of the proxy to use to connect to Deep Security Manager. Set to null for no proxy. 
	 * @param validateCertificate A Boolean value of true causes the script to validate that Deep Security Manager is using a valid TLS certificate from a trusted certificate authority (CA) when downloading the agent installer. When null, the default of false is used. 
	 * @param activate A Boolean value of true causes the script to activate the agent. When null, the default of false is used;
	 * @param computerGroupID The Integer ID of the computer group to which the computer is added. Set to null for no computer group. 
	 * @param policyID The Integer ID of the policy to assign to the computer. Set to null to assign no policy. 
	 * @param relayID The Integer ID of the relay to assign to the computer for obtaining updates. Set to null to assign no relay. 
	 * @param relayProxyID The Integer ID of the proxy that the agent uses to connect to the relay. Set to null for no proxy. 
	 * @param apiVersion A String that identifies the version of the API to use, such as "v1".
	 * @return A String that contains the deployment script.
	 * @throws ApiException if a problem occurs when generating the script on Deep Security Manager. 
	 */
	public static String getAgentDeploymentScript(PlatformEnum platform, Integer dsmProxyID, Boolean validateCertificate, Boolean activate, Integer computerGroupID, Integer policyID, Integer relayID, Integer relayProxyID, String apiVersion) throws ApiException {
		
		// Create the AgentDeplotmentScript object
		AgentDeploymentScript deployScript = new AgentDeploymentScript();
		deployScript.setPlatform(platform);
		deployScript.setDsmProxyID(dsmProxyID);
		deployScript.setValidateCertificateRequired(validateCertificate);
		deployScript.setActivationRequired(activate);
		deployScript.setComputerGroupID(computerGroupID);
		deployScript.setPolicyID(policyID);
		deployScript.setRelayGroupID(relayID);
		deployScript.setRelayProxyID(relayProxyID);
		
		// Get the script from Deep Security Manager
		AgentDeploymentScriptsApi agentDeploymentScriptsApi = new AgentDeploymentScriptsApi();
		deployScript = agentDeploymentScriptsApi.generateAgentDeploymentScript(deployScript, apiVersion);
		
		// Return the script
		return deployScript.getScriptBody();
	}
}
