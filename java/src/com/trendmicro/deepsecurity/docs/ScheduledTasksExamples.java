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
import com.trendmicro.deepsecurity.api.ScheduledTasksApi;
import com.trendmicro.deepsecurity.model.CheckForSecurityUpdatesTaskParameters;
import com.trendmicro.deepsecurity.model.ComputerFilter;
import com.trendmicro.deepsecurity.model.DailyScheduleParameters;
import com.trendmicro.deepsecurity.model.DiscoverComputersTaskParameters;
import com.trendmicro.deepsecurity.model.MonthlyScheduleParameters;
import com.trendmicro.deepsecurity.model.OnceOnlyScheduleParameters;
import com.trendmicro.deepsecurity.model.ScheduleDetails;
import com.trendmicro.deepsecurity.model.ScheduledTask;

public class ScheduledTasksExamples {

	/**
	 * Creates a ScheduleDetails object for use with a scheduled task for daily execution using a custom interval.
	 * 
	 * @param customInterval The interval for the runs. For example 2 to run every second day.
	 * @param startTime The epoch time in milliseconds when the scheduled task first runs.
	 * @return The created ScheduleDetails object.
	 */
	public static ScheduleDetails createDailyScheduleDetails(Integer customInterval, Long startTime) {

		// Create a ScheduleDetails object and set the recurrence type
		ScheduleDetails dailySchedule = new ScheduleDetails();
		dailySchedule.setRecurrenceType(ScheduleDetails.RecurrenceTypeEnum.DAILY);

		// Specify when the task runs
		DailyScheduleParameters dailyScheduleParameters = new DailyScheduleParameters();

		// Use a custom frequency type to run the task at daily intervals.
		// Every day and only weekdays are other available frequency types.
		dailyScheduleParameters.setFrequencyType(DailyScheduleParameters.FrequencyTypeEnum.CUSTOM);
		dailyScheduleParameters.setCustomInterval(customInterval);
		dailyScheduleParameters.setStartTime(startTime);

		// Add the schedule parameters to the schedule details
		dailySchedule.setDailyScheduleParameters(dailyScheduleParameters);

		return dailySchedule;
	}

	/**
	 * Creates a ScheduleDetails object to use with a scheduled task for quarterly execution (every 3 months).
	 * 
	 * @param day The day of the month on which the scheduled task runs.
	 * @return The created ScheduleDetails object.
	 */
	public static ScheduleDetails createQuarterlyScheduleDetails(Integer day) {

		// Create a ScheduleDetails object and set the recurrence type
		ScheduleDetails quarterlySchedule = new ScheduleDetails();
		quarterlySchedule.setRecurrenceType(ScheduleDetails.RecurrenceTypeEnum.MONTHLY);

		// Specify when the task runs
		MonthlyScheduleParameters monthlyScheduleParameters = new MonthlyScheduleParameters();

		// Set the schedule to run on a specific day of the month.
		// Other options are the last day of the month, or a specific weekday of a
		// specific week
		monthlyScheduleParameters.setFrequencyType(MonthlyScheduleParameters.FrequencyTypeEnum.DAY_OF_MONTH);

		// Set the day
		monthlyScheduleParameters.setDayOfMonth(day);

		// Set the months to be quarterly
		monthlyScheduleParameters.addMonthsItem(MonthlyScheduleParameters.MonthsEnum.JANUARY);
		monthlyScheduleParameters.addMonthsItem(MonthlyScheduleParameters.MonthsEnum.APRIL);
		monthlyScheduleParameters.addMonthsItem(MonthlyScheduleParameters.MonthsEnum.JULY);
		monthlyScheduleParameters.addMonthsItem(MonthlyScheduleParameters.MonthsEnum.OCTOBER);

		// Add the schedule parameters to the schedule details
		quarterlySchedule.setMonthlyScheduleParameters(monthlyScheduleParameters);

		return quarterlySchedule;
	}

	/**
	 * Creates a scheduled task that runs every two days to discover new computers on the network. The task does not run now.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the scheduled task on Deep Security Manager.
	 * @return The created ScheduledTask object.
	 */
	public static ScheduledTask createDiscoverComputersScheduledTask(String apiVersion) throws ApiException {

		// Create the ScheduledTask object and set the name and type. Do not run now.
		ScheduledTask discoverComputersTask = new ScheduledTask();
		discoverComputersTask.setName("Discover Computers - Daily");
		discoverComputersTask.setType(ScheduledTask.TypeEnum.DISCOVER_COMPUTERS);
		discoverComputersTask.setRunNow(Boolean.FALSE);

		// Call the createDailyScheduleDetails method to obtain a daily ScheduleDetails
		// object.
		// Set the start time to 11:00 DST.
		Long startTime = Long.valueOf(1553007600000L);
		ScheduleDetails scheduleDetails = ScheduledTasksExamples.createDailyScheduleDetails(Integer.valueOf(2), startTime);
		discoverComputersTask.setScheduleDetails(scheduleDetails);

		// Create a DiscoverComputersTaskParameters object.
		// The scan applies to a range of IP addresses, and scans discovered computers
		// for open ports.
		DiscoverComputersTaskParameters taskParameters = new DiscoverComputersTaskParameters();
		taskParameters.setDiscoveryType(DiscoverComputersTaskParameters.DiscoveryTypeEnum.RANGE);
		taskParameters.setIprangeLow("192.168.1.1");
		taskParameters.setIprangeHigh("192.168.1.100");
		taskParameters.setScanDiscoveredComputers(Boolean.TRUE);
		discoverComputersTask.setDiscoverComputersTaskParameters(taskParameters);

		// Create the scheduled task on Deep Security Manager.
		ScheduledTasksApi scheduledTasksApi = new ScheduledTasksApi();
		return scheduledTasksApi.createScheduledTask(discoverComputersTask, apiVersion);
	}

	/**
	 * Creates a scheduled task that checks for security updates. The scheduled task runs immediately after it is created, and is
	 * deleted thereafter.
	 * 
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when creating the scheduled task on Deep Security Manager.
	 * @return The ScheduledTask object that was created.
	 */
	public static ScheduledTask checkForSecurityUpdatesUsingScheduledTask(String apiVersion) throws ApiException {

		// Set the name and task type
		ScheduledTask checkForSecurityUpdates = new ScheduledTask();
		checkForSecurityUpdates.setName("Check For Security Updates");
		checkForSecurityUpdates.setType(ScheduledTask.TypeEnum.CHECK_FOR_SECURITY_UPDATES);

		// Run when the scheduled task is created
		checkForSecurityUpdates.setRunNow(Boolean.TRUE);

		// Use a once-only recurrence
		ScheduleDetails scheduleDetails = new ScheduleDetails();
		scheduleDetails.setRecurrenceType(ScheduleDetails.RecurrenceTypeEnum.NONE);

		// Set the recurrence count to 1 so that the task is deleted after running
		scheduleDetails.setRecurrenceCount(Integer.valueOf(1));
		OnceOnlyScheduleParameters scheduleParameters = new OnceOnlyScheduleParameters();

		// The start time is not important because it is deleted after running
		scheduleParameters.setStartTime(Long.valueOf(0L));
		scheduleDetails.setOnceOnlyScheduleParameters(scheduleParameters);
		checkForSecurityUpdates.setScheduleDetails(scheduleDetails);

		// Scan all computers
		ComputerFilter computerFilter = new ComputerFilter();
		computerFilter.setType(ComputerFilter.TypeEnum.ALL_COMPUTERS);

		// Create the task parameters object and add the computer filter
		CheckForSecurityUpdatesTaskParameters taskParameters = new CheckForSecurityUpdatesTaskParameters();
		taskParameters.setComputerFilter(computerFilter);

		checkForSecurityUpdates.setCheckForSecurityUpdatesTaskParameters(taskParameters);

		// Create the scheduled task
		ScheduledTasksApi scheduledTasksApi = new ScheduledTasksApi();
		return scheduledTasksApi.createScheduledTask(checkForSecurityUpdates, apiVersion);
	}

	/**
	 * Runs a scheduled task and modifies the task schedule to run at the current time.
	 * 
	 * @param scheduledTaskID The ID of the scheduled task.
	 * @param apiVersion The version of the API to use.
	 * @throws ApiException if a problem occurs when modifying the scheduled task on Deep Security Manager.
	 * @return The modified ScheduledTask.
	 */
	public static ScheduledTask runScheduledTask(Integer scheduledTaskID, String apiVersion) throws ApiException {

		// Create the ScheduledTask object set to run now
		ScheduledTask scheduledTask = new ScheduledTask();
		scheduledTask.runNow(Boolean.TRUE);

		// Modify the scheduled task on Deep Security Manager
		ScheduledTasksApi scheduledTasksApi = new ScheduledTasksApi();
		return scheduledTasksApi.modifyScheduledTask(scheduledTaskID, scheduledTask, apiVersion);
	}
}
