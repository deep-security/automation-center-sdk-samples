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

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.AntiMalwareConfigurationsApi;
import com.trendmicro.deepsecurity.api.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.IntrusionPreventionRulesApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.model.AntiMalwareComputerExtension;
import com.trendmicro.deepsecurity.model.AntiMalwareConfiguration;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.ComputerModuleStatus.AgentStatusEnum;
import com.trendmicro.deepsecurity.model.ComputerModuleStatus.ApplianceStatusEnum;
import com.trendmicro.deepsecurity.model.ComputerStatus;
import com.trendmicro.deepsecurity.model.Computers;
import com.trendmicro.deepsecurity.model.Expand;
import com.trendmicro.deepsecurity.model.IntrusionPreventionAssignments;
import com.trendmicro.deepsecurity.model.IntrusionPreventionComputerExtension;
import com.trendmicro.deepsecurity.model.IntrusionPreventionRule;
import com.trendmicro.deepsecurity.model.IntrusionPreventionRules;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchCriteria.StringTestEnum;
import com.trendmicro.deepsecurity.model.SearchFilter;
import com.trendmicro.deepsecurity.model.IntrusionPreventionPolicyExtension;

/**
 * Obtains the status and configuration information of computers.
 */
public class ComputerStatusExamples {

	/**
	 * Obtains agent and appliance status for all computers and provides the results as comma-separated values.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when obtaining the list of computers.
	 * @return A String value that can be saved as a CSV file.
	 */
	public static String getComputerStatuses(String apiVersion) throws ApiException {

		// Add column titles to comma-separated values
		StringBuilder csv = new StringBuilder("Host Name, Agent or Appliance, Status, Status Messages, Tasks\r\n");

		// Include computer status information in the returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.COMPUTER_STATUS);

		// Get all computers
		ComputersApi computersApi = new ComputersApi();
		Computers computers = computersApi.listComputers(expand.list(), Boolean.FALSE, apiVersion);

		for (Computer computer : computers.getComputers()) {
			List<String> computerInfo = new ArrayList<>();

			// Report on computers with no agent or appliance
			if (computer.getAgentFingerPrint() == null && computer.getApplianceFingerPrint() == null) {

				// Hostname and protection type
				computerInfo.add(computer.getHostName());
				computerInfo.add("None");

				// Agent/appliance status and status messages
				computerInfo.add("No agent/appliance");
				String statusMessages = (computer.getComputerStatus().getAgentStatus() != null) ? computer.getComputerStatus().getAgentStatusMessages().toString() : "";
				computerInfo.add(statusMessages);

				// Add to CSV string
				csv.append(formatForCSV(computerInfo));

			} else {
				// Report on problem agents and appliances
				boolean agentIsActive = computer.getComputerStatus().getAgentStatus() == ComputerStatus.AgentStatusEnum.ACTIVE;
				boolean applianceIsActive = computer.getComputerStatus().getApplianceStatus() == ComputerStatus.ApplianceStatusEnum.ACTIVE;

				// Agent is installed but is not active
				if (computer.getAgentFingerPrint() != null && !agentIsActive) {

					// Hostname and protection type
					computerInfo.add(computer.getHostName());
					computerInfo.add("Agent");

					// Agent status, status messages, and tasks
					String agentStatus = (computer.getComputerStatus().getAgentStatus() != null) ? computer.getComputerStatus().getAgentStatus().getValue() : "";
					computerInfo.add(agentStatus);
					String statusMessages = (computer.getComputerStatus().getAgentStatusMessages() != null) ? computer.getComputerStatus().getAgentStatusMessages().toString() : "";
					computerInfo.add(statusMessages);
					String agentTasks = (computer.getTasks() != null) ? computer.getTasks().getAgentTasks().toString() : "";
					computerInfo.add(agentTasks);
					// Add to CSV string
					csv.append(formatForCSV(computerInfo));
					computerInfo.clear();
				}

				// Appliance is installed but is not active
				if (computer.getApplianceFingerPrint() != null && !applianceIsActive) {

					// Hostname and protection type
					computerInfo.add(computer.getHostName());
					computerInfo.add("Appliance");

					// Applicance status, messages, and tasks
					String applianceStatus = (computer.getComputerStatus().getApplianceStatus() != null) ? computer.getComputerStatus().getApplianceStatus().getValue() : "";
					computerInfo.add(applianceStatus);
					String applianceStatusMessages = computer.getComputerStatus().getApplianceStatusMessages() != null ? computer.getComputerStatus().getApplianceStatusMessages().toString() : "";
					computerInfo.add(applianceStatusMessages);
					String applianceTasks = (computer.getTasks() != null) ? computer.getTasks().getApplianceTasks().toString() : "";
					computerInfo.add(applianceTasks);
					((ArrayList<String>)computerInfo).trimToSize();
					// Add to CSV string
					csv.append(formatForCSV(computerInfo));
				}
			}
		}
		return csv.toString();
	}

	/**
	 * Converts a List of strings into a String of comma-separated values.
	 * 
	 * @return A String that contains the comma-separated values.
	 */
	private static String formatForCSV(List<String> values) {
		StringBuilder csvLine = new StringBuilder();
		for (int i = 0; i < values.size(); i++) {
			csvLine.append("\"" + values.get(i) + "\"");
			if (i != values.size() - 1) {
				csvLine.append(",");
			} else {
				csvLine.append("\r\n");
			}
		}
		return csvLine.toString();
	}

	/**
	 * Obtains agent and appliance status for the Anti-Malware module of all computers and provides the results as comma-separated
	 * values.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when obtaining a list of computers.
	 * @return A String value that can be saved as a CSV file.
	 */
	public static String getAntiMalwareStatusForComputers(String apiVersion) throws ApiException {

		// Add titles to comma-separated values
		StringBuilder csv = new StringBuilder("Host Name, Module State, Agent or Appliance, Status, Status Message\r\n ");

		// Include Anti-Malware information in the returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.ANTI_MALWARE);

		// Get a list of computers
		ComputersApi computersApi = new ComputersApi();
		Computers computers = computersApi.listComputers(expand.list(), Boolean.FALSE, apiVersion);

		for (Computer computer : computers.getComputers()) {

			// Module information to add to the CSV string
			List<String> moduleInfo = new ArrayList<>();

			AgentStatusEnum agentStatus = computer.getAntiMalware().getModuleStatus().getAgentStatus();
			ApplianceStatusEnum applianceStatus = computer.getAntiMalware().getModuleStatus().getApplianceStatus();

			// Agents that are not active for the module
			if (agentStatus != null && agentStatus != AgentStatusEnum.ACTIVE) {

				// Hostname
				moduleInfo.add(computer.getHostName());

				// Module state
				moduleInfo.add(computer.getAntiMalware().getState().getValue());

				// Agent status and status message
				moduleInfo.add("Agent");
				moduleInfo.add(agentStatus.getValue());
				moduleInfo.add(computer.getAntiMalware().getModuleStatus().getAgentStatusMessage());

				// Add to the CSV string
				csv.append(formatForCSV(moduleInfo));
				moduleInfo.clear();
			}

			// Appliances that are not active for the module
			if (applianceStatus != null && applianceStatus != ApplianceStatusEnum.ACTIVE) {

				// Hostname
				moduleInfo.add(computer.getHostName());

				// Module state
				moduleInfo.add(computer.getAntiMalware().getState().getValue());

				// Appliance status and status messages
				moduleInfo.add("Appliance");
				moduleInfo.add(computer.getAntiMalware().getModuleStatus().getApplianceStatus().getValue());
				moduleInfo.add(computer.getAntiMalware().getModuleStatus().getApplianceStatusMessage());

				// Add to the CSV string
				csv.append(formatForCSV(moduleInfo));
			}
		}
		return csv.toString();
	}

	/**
	 * Obtains certain properties of the Anti-Malware module for all computers
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when obtaining the list of computers.
	 * @return A list of Map objects of computer hostnames (the key) and the a list of properties (the value).
	 */
	public static List<Map<String, Object>> checkAntiMalware(String apiVersion) throws ApiException {
		List<Map<String, Object>> amStatuses = new ArrayList<>(); // Stores the properties

		ComputersApi computersApi = new ComputersApi();
		AntiMalwareConfigurationsApi amConfigApi = new AntiMalwareConfigurationsApi();

		// Include Anti-Malware information in the returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.ANTI_MALWARE, Expand.OptionsEnum.COMPUTER_SETTINGS);

		// Get all computers
		Computers computers = computersApi.listComputers(expand.list(), Boolean.FALSE, apiVersion);
		for (Computer computer : computers.getComputers()) {

			// Get properties for each computer
			Map<String, Object> amStatus = new HashMap<>(); // Stores the computer host names and the properties
			amStatus.put("hostname", computer.getHostName());
			AntiMalwareComputerExtension antiMalware = computer.getAntiMalware();

			// Get Anti-Malware state
			String state = antiMalware.getState().getValue();
			amStatus.put("state", state);

			// Smart Scan enabled?
			amStatus.put("AntiMalwareSettingSmartScanState", computer.getComputerSettings().getAntiMalwareSettingSmartScanState().getValue());

			// Scanned directories
			Integer realTimeScanConfigID = antiMalware.getRealTimeScanConfigurationID();
			if (realTimeScanConfigID != null && realTimeScanConfigID.intValue() > 0) {
				AntiMalwareConfiguration amc = amConfigApi.describeAntiMalware(realTimeScanConfigID, apiVersion);
				amStatus.put("directories", amc.getDirectoriesToScan());
				if (amc.getDirectoriesToScan() == AntiMalwareConfiguration.DirectoriesToScanEnum.DIRECTORY_LIST) {
					amStatus.put("scan-dirs", amc.getDirectoryListID());
				}
			}
			amStatuses.add(amStatus);
		}
		return amStatuses;
	}

	/**
	 * Finds the intrusion prevention rules for a CVE.
	 * 
	 * @param cve The CVE ID.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when searching for rules.
	 * @return A list of the Intrusion Prevention rule IDs. The list is empty if no rule is found.
	 */
	public static List<Integer> findRuleForCVE(String cve, String apiVersion) throws ApiException {

		List<Integer> ruleIDs = new ArrayList<>();
		IntrusionPreventionRulesApi intrusionPreventionRulesApi = new IntrusionPreventionRulesApi();

		// Create a search filter to find the rules
		SearchFilter searchFilter = new SearchFilter();

		SearchCriteria searchCriteria = new SearchCriteria();
		searchCriteria.fieldName("CVE");
		searchCriteria.setStringValue("%" + cve + "%");
		searchCriteria.setStringTest(StringTestEnum.EQUAL);

		searchFilter.addSearchCriteriaItem(searchCriteria);

		// Perform the search
		IntrusionPreventionRules intrusionPreventionRules = intrusionPreventionRulesApi.searchIntrusionPreventionRules(searchFilter, apiVersion);

		// Get the rule IDs from the results
		for (IntrusionPreventionRule rule : intrusionPreventionRules.getIntrusionPreventionRules()) {
			ruleIDs.add(rule.getID());
		}
		return ruleIDs;
	}

	/**
	 * Finds computers that do not have a specific intrusion prevention rule applied.
	 * 
	 * @param ruleID The rule ID.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when obtaining the list of computers.
	 * @return A Computers object that contains the computers that do not have the rule applied.
	 */
	public static Computers checkComputersForIPRule(Integer ruleID, String apiVersion) throws ApiException {
		Computers needsRule = new Computers();
		ComputersApi computersApi = new ComputersApi();

		// Include Intrusion Prevention information in the returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.INTRUSION_PREVENTION);

		Computers computers = computersApi.listComputers(expand.list(), Boolean.FALSE, apiVersion);
		for (Computer computer : computers.getComputers()) {
			IntrusionPreventionComputerExtension ipExt = computer.getIntrusionPrevention();
			if (ipExt.getRuleIDs() == null || !ipExt.getRuleIDs().contains(ruleID)) {
				needsRule.addComputersItem(computer);
			}
		}
		return needsRule;
	}

	/**
	 * Adds an Intrusion Prevention rule to the policies of a list of computers.
	 * 
	 * @param needsRule A Computers object that contains computers that require the protection of the rule.
	 * @param ruleID The ID of the rule to add to the policies.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 */
	public static void applyRuleToPolicies(Computers needsRule, Integer ruleID, String apiVersion) throws ApiException {

		// Stores IDs of policies to modify (HashSet ensures no duplicates)
		Set<Integer> policyIDs = new HashSet<>();

		// Get the policy IDs of each computer
		List<Computer> computers = needsRule.getComputers();
		for (Computer computer : computers) {
			if (computer.getPolicyID() != null) {
				policyIDs.add(computer.getPolicyID());
			}
		}

		PoliciesApi policiesApi = new PoliciesApi();
		for (Integer policyID : policyIDs) {

			// Get the current list of rules from the policy
			List<Integer> currentRules = policiesApi.describePolicy(policyID, Boolean.FALSE, apiVersion).getIntrusionPrevention().getRuleIDs();

			// Add the new and existing intrusion prevention rules to a policy
			IntrusionPreventionPolicyExtension intrusionPreventionPolicyExtension = new IntrusionPreventionPolicyExtension();
			intrusionPreventionPolicyExtension.setRuleIDs(currentRules);
			intrusionPreventionPolicyExtension.addRuleIDsItem(ruleID);
			Policy policy = new Policy();
			policy.setIntrusionPrevention(intrusionPreventionPolicyExtension);

			// Configure sending policy updates when the policy changes
			policy.setAutoRequiresUpdate(Policy.AutoRequiresUpdateEnum.ON);

			// Modify the policy on Deep Security Manager
			policiesApi.modifyPolicy(policyID, policy, Boolean.FALSE, apiVersion);
		}
	}

	/**
	 * Obtains the list of recommended Intrusion Prevention rules to apply to a computer, according to the results of the last
	 * recommendation scan.
	 * 
	 * @param computerID The ID of the computer that was scanned.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when getting the list of recommended rules.
	 * @return A list of rule IDs, or null if no scan was performed.
	 */
	public static List<Integer> getIntrusionPreventionRecommendations(Integer computerID, String apiVersion) throws ApiException {
		ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi ipRecosApi = new ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi();
		IntrusionPreventionAssignments ipAssignments = null;
		ipAssignments = ipRecosApi.listIntrusionPreventionRuleIDsOnComputer(computerID, Boolean.FALSE, apiVersion);

		return ipAssignments.getRecommendedToAssignRuleIDs();
	}

	/**
	 * For all computers, obtains the date of the last recommendation scan and the scan status.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when getting the list of computers and recommended rules.
	 * @return A String that contains the recommendation scan information for all computers, in CSV format.
	 */
	public static String getDateOfLastRecommendationScan(String apiVersion) throws ApiException {

		// Add the current date to the report
		StringBuilder csv = new StringBuilder(LocalDateTime.now().toString() + "\r\n");

		// Add column titles to comma-separated values
		csv.append("Host Name, Last Scan Date, Scan Status\r\n");

		// Include minimal information in the returned Computer objects
		Expand expand = new Expand(Expand.OptionsEnum.NONE);

		// Get all computers
		ComputersApi computersApi = new ComputersApi();
		Computers computers = computersApi.listComputers(expand.list(), Boolean.FALSE, apiVersion);

		for (Computer computer : computers.getComputers()) {
			List<String> recoScanInfo = new ArrayList<>();

			// Capture the host name
			recoScanInfo.add(computer.getHostName());
			
			// Get the recommendation scan information
			ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi ipRulesRecApi = new ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi();
			Boolean overrides = Boolean.FALSE;
			IntrusionPreventionAssignments ipAssignments = ipRulesRecApi.listIntrusionPreventionRuleIDsOnComputer(computer.getID(), overrides, apiVersion);

			// Last scan date
			if (ipAssignments.getLastRecommendationScanDate() != null) {
				Long lastScanSinceEpoch = ipAssignments.getLastRecommendationScanDate();
				LocalDateTime lastScanUTC = LocalDateTime.ofInstant(Instant.ofEpochMilli(lastScanSinceEpoch.longValue()), ZoneOffset.UTC);
				recoScanInfo.add(lastScanUTC.toString());
			} else {
				recoScanInfo.add("No scan on record");
			}
			
			// Scan status
			recoScanInfo.add(ipAssignments.getRecommendationScanStatus().getValue());
			
			// Add to the CSV string
			csv.append(formatForCSV(recoScanInfo));
		}
		return csv.toString();
	}
}
