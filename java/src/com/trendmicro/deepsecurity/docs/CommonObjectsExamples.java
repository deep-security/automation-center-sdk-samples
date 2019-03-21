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

import java.util.ArrayList;
import java.util.List;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.AntiMalwareConfigurationsApi;
import com.trendmicro.deepsecurity.api.DirectoryListsApi;
import com.trendmicro.deepsecurity.api.LogInspectionRulesApi;
import com.trendmicro.deepsecurity.api.SchedulesApi;
import com.trendmicro.deepsecurity.model.AntiMalwareConfiguration;
import com.trendmicro.deepsecurity.model.DirectoryList;
import com.trendmicro.deepsecurity.model.LogFile;
import com.trendmicro.deepsecurity.model.LogFiles;
import com.trendmicro.deepsecurity.model.LogInspectionRule;
import com.trendmicro.deepsecurity.model.Schedule;

/**
 * Configures objects that are used for configuring protection modules.
 */
public class CommonObjectsExamples {

	/**
	 * Creates a basic Log Inspection rule that monitors a log file for errors.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the rule on Deep Security Manager.
	 * @return The Log Inspection rule.
	 */
	public static LogInspectionRule createLogInspectionRule(String apiVersion) throws ApiException {

		// Create the rule and add basic information
		LogInspectionRule liRule = new LogInspectionRule();
		liRule.setName("Inspect Log for Error");
		liRule.setDescription("A simple rule.");

		// Log files to inspect
		LogFile logFile = new LogFile();
		logFile.setLocation("C:\\logfile.log");
		logFile.setFormat(LogFile.FormatEnum.EVENTLOG);
		LogFiles logFiles = new LogFiles();
		logFiles.addLogFilesItem(logFile);
		liRule.setLogFiles(logFiles);

		// Template type is Basic Rule
		liRule.setTemplate(LogInspectionRule.TemplateEnum.BASIC_RULE);

		// Set the pattern
		liRule.setPattern("^ERROR");
		liRule.setPatternType(LogInspectionRule.PatternTypeEnum.STRING);

		// Description and group
		liRule.setRuleDescription("Test Rule Description");
		List<String> groups = new ArrayList<>();
		groups.add("Windows Rules");
		liRule.setGroups(groups);

		// Add the rule to Deep Security Manager
		LogInspectionRulesApi liRulesApi = new LogInspectionRulesApi();
		return liRulesApi.createLogInspectionRule(liRule, apiVersion);
	}

	/**
	 * Creates a log Inspection rule using XML.
	 * 
	 * @param xml The base-64-encoded XML (contains patterns and groups)
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the rule on Deep Security Manager.
	 * @return The Log Inspection rule.
	 */
	public static LogInspectionRule createLogInspectionRuleXML(String xml, String apiVersion) throws ApiException {

		// Create the rule and add basic information
		LogInspectionRule liRule = new LogInspectionRule();
		liRule.setName("Inspect Log for Error XML");
		liRule.setDescription("A simple rule.");

		// Log files to inspect
		LogFile logFile = new LogFile();
		logFile.setLocation("C:\\logfile.log");
		logFile.setFormat(LogFile.FormatEnum.EVENTLOG);
		LogFiles logFiles = new LogFiles();
		logFiles.addLogFilesItem(logFile);
		liRule.setLogFiles(logFiles);

		// Template type is Custom
		liRule.setTemplate(LogInspectionRule.TemplateEnum.CUSTOM);

		// Set the XML
		liRule.setRuleXML(xml);

		// Add the rule to Deep Security Manager
		LogInspectionRulesApi liRulesApi = new LogInspectionRulesApi();
		return liRulesApi.createLogInspectionRule(liRule, apiVersion);
	}

	/**
	 * Adds a directory to an existing directory list.
	 * 
	 * @param dirListID The ID of the directory list.
	 * @param dirPath The path of the directory to add to the list.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the directory list on Deep Security Manager.
	 * @return The modified directory list.
	 */
	public static DirectoryList addItemToDirectoryList(Integer dirListID, String dirPath, String apiVersion) throws ApiException {

		// Obtain the directory list if it exists
		DirectoryListsApi dirListsApi = new DirectoryListsApi();
		DirectoryList dirList = dirListsApi.describeDirectoryList(dirListID, apiVersion);

		// Create a DirectoryList object and add the existing and additional directory
		DirectoryList dirListWithDirectory = new DirectoryList();
		dirListWithDirectory.setItems(dirList.getItems());
		dirListWithDirectory.addItemsItem(dirPath);

		// Modify the list and update on Deep Security Manager
		return dirListsApi.modifyDirectoryList(dirList.getID(), dirListWithDirectory, apiVersion);
	}

	/**
	 * Sets the exclusion directory list for a policy's anti-malware real-time scan configuration.
	 * 
	 * @param scanConfigID The ID of the scan configuration.
	 * @param dirListID The ID of the exclusion directory list to use.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the malware scan configuration on Deep Security Manager.
	 * @return The modified malware scan configuration.
	 */
	public static AntiMalwareConfiguration setExclusionDirRealTimeScan(Integer scanConfigID, Integer dirListId, String apiVersion) throws ApiException {

		// create a real time scan configuration object
		AntiMalwareConfiguration realtimeConfig = new AntiMalwareConfiguration();

		// Set the ID of the directory exclusion list
		realtimeConfig.setExcludedDirectoryListID(dirListId);

		// Update Deep Security Manager
		AntiMalwareConfigurationsApi amConfigsApi = new AntiMalwareConfigurationsApi();
		return amConfigsApi.modifyAntiMalware(scanConfigID, realtimeConfig, apiVersion);
	}

	/**
	 * Creates a schedule for an activity that occurs during business hours.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the schedule on Deep Security Manager.
	 * @return The ID of the created schedule.
	 */
	public static Integer createBusinessHoursSchedule(String apiVersion) throws ApiException {
		Schedule schedule = new Schedule();
		schedule.setName("Normal business hours");
		List<Boolean> hours = new ArrayList<>();
		for (int i = 0; i < 7; i++) {
			if (i != 0 && i != 6) {
				// true from Monday - Friday
				for (int j = 0; j < 24; j++) {
					if (j > 8 && j < 17) {
						// true from 9AM to 5PM
						hours.add(Boolean.TRUE);
					} else {
						hours.add(Boolean.FALSE);
					}
				}
			} else {
				for (int k = 0; k < 24; k++) {
					hours.add(Boolean.FALSE);
				}
			}
		}
		// Add hours to schedule
		schedule.setHoursOfWeek(hours);

		// Add to Deep Security Manager
		SchedulesApi schedulesApi = new SchedulesApi();
		schedule = schedulesApi.createSchedule(schedule, apiVersion);

		return schedule.getID();
	}
}
