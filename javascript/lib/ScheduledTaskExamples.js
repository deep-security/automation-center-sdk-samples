/*
 * Copyright 2019 Trend Micro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Creates a ScheduleDetails object for use with a scheduled task for daily execution
 * using a custom interval.
 * @param {Number} customInterval The interval for the runs. For example 2 to run every second day.
 * @param {Number} startTime	The epoch time in milliseconds when the scheduled task first runs.
 * @param {ApiClient} api The Deep Security API exports.
 * @returns A ScheduleDetails object.
 */
exports.createDailyScheduleDetails = function(customInterval, startTime, api) {
  // Create a ScheduleDetails object and set the recurrence type
  const dailySchedule = new api.ScheduleDetails();
  dailySchedule.recurrenceType = api.ScheduleDetails.RecurrenceTypeEnum.daily;

  // Specify when the task runs
  const dailyScheduleParameters = new api.DailyScheduleParameters();

  //Use a custom frequency type to run the task at daily intervals
  //Every day and only weekdays are other available frequency types
  dailyScheduleParameters.frequencyType = api.DailyScheduleParameters.FrequencyTypeEnum.custom;
  dailyScheduleParameters.customInterval = customInterval;
  dailyScheduleParameters.startTime = startTime;

  //Add the schedule parameters to the schedule details
  dailySchedule.dailyScheduleParameters = dailyScheduleParameters;

  return dailySchedule;
};

/*
 * Creates a ScheduleDetails object to use with a scheduled task for quarterly execution (every 3 months).
 * @param {Number} day The day of the month on which the scheduled task runs.
 * @param {ApiClient} api The Deep Security API exports.
 * @return A ScheduleDetails object.
 */
exports.createQuarterlyScheduleDetails = function(day, api) {
  // Create a ScheduleDetails object and set the recurrence type
  const quarterlySchedule = new api.ScheduleDetails();
  quarterlySchedule.recurrenceType = api.ScheduleDetails.RecurrenceTypeEnum.monthly;

  // Specify when the task runs
  const monthlyScheduleParameters = new api.MonthlyScheduleParameters();

  //Set the schedule to run on a specific day of the month.
  //Other options are the last day of the month, or a specific weekday of a specific week
  monthlyScheduleParameters.frequencyType = api.MonthlyScheduleParameters.FrequencyTypeEnum["day-of-month"];
  monthlyScheduleParameters.dayOfMonth = day;

  // Set the months to be quarterly
  monthlyScheduleParameters.months = [
    api.MonthlyScheduleParameters.MonthsEnum.january,
    api.MonthlyScheduleParameters.MonthsEnum.april,
    api.MonthlyScheduleParameters.MonthsEnum.july,
    api.MonthlyScheduleParameters.MonthsEnum.october
  ];

  // Add the schedule parameters to the schedule details
  quarterlySchedule.monthlyScheduleParameters = monthlyScheduleParameters;

  return quarterlySchedule;
};

/*
 * Creates a scheduled task that runs daily to discover new computers on the network.
 * The task does not run now.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the ScheuledTask.
 */
exports.createDiscoverComputersScheduledTask = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the ScheduledTask object and set the name and type. Do not run now.
    const discoverComputersTask = new api.ScheduledTask();
    discoverComputersTask.name = "Discover Computers - Daily";
    discoverComputersTask.type = api.ScheduledTask.TypeEnum["discover-computers"];
    discoverComputersTask.runNow = false;

    // Call the createDailyScheduleDetails method to obtain a daily ScheduleDetails object
    // Set the start time to 03:00 DST
    discoverComputersTask.scheduleDetails = module.exports.createDailyScheduleDetails(2, 1536030000000, api);

    // Create a DiscoverComputersTaskParameters object.
    // The scan applies to a range of IP addresses, and scans discovered computers for open ports
    const taskParameters = new api.DiscoverComputersTaskParameters();
    taskParameters.discoveryType = api.DiscoverComputersTaskParameters.DiscoveryTypeEnum.range;
    taskParameters.iprangeLow = "192.168.60.0";
    taskParameters.iprangeHigh = "192.168.60.255";
    taskParameters.scanDiscoveredComputers = true;
    discoverComputersTask.discoverComputersTaskParameters = taskParameters;

    // Create the scheduled task on Deep Security Manager
    const scheduledTasksApi = new api.ScheduledTasksApi();
    scheduledTasksApi
      .createScheduledTask(discoverComputersTask, apiVersion)
      .then(scheduledTask => {
        resolve(scheduledTask.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Creates a scheduled task that checks for security updates.
 * The scheduled task runs immediately after it is created, and is
 * deleted thereafter.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the ScheuledTask.
 */
exports.checkForSecurityUpdatesUsingScheduledTask = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Set the name and task type
    const checkForSecurityUpdates = new api.ScheduledTask();
    checkForSecurityUpdates.name = "Check For Security Updates";
    checkForSecurityUpdates.type = api.ScheduledTask.TypeEnum["check-for-security-updates"];

    // Run when the scheduled task is created
    checkForSecurityUpdates.runNow = true;

    // Use a once-only recurrence
    const scheduleDetails = new api.ScheduleDetails();
    scheduleDetails.recurrenceType = api.ScheduleDetails.RecurrenceTypeEnum.none;

    // Set the recurrence count to 1 so that the task is deleted after running
    scheduleDetails.recurrenceCount = 1;
    const scheduleParameters = new api.OnceOnlyScheduleParameters();

    // The start time is not important because it is deleted after running
    scheduleParameters.startTime = 0;
    scheduleDetails.onceOnlyScheduleParameters = scheduleParameters;
    checkForSecurityUpdates.scheduleDetails = scheduleDetails;

    // Scan all computers
    const computerFilter = new api.ComputerFilter();
    computerFilter.type = api.ComputerFilter.TypeEnum["all-computers"];

    // Create the task parameters object and add the computer filter
    const taskParameters = new api.CheckForSecurityUpdatesTaskParameters();
    taskParameters.computerFilter = computerFilter;

    checkForSecurityUpdates.checkForSecurityUpdatesTaskParameters = taskParameters;

    // Create the scheduled task on Deep Security Manager
    const scheduledTasksApi = new api.ScheduledTasksApi();
    scheduledTasksApi
      .createScheduledTask(checkForSecurityUpdates, apiVersion)
      .then(scheduledTask => {
        resolve(scheduledTask.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Runs a scheduled task.
 * @param scheduledTaskID The ID of the scheduled task.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ScheduledTask object.
 */
exports.runScheduledTask = function(scheduledTaskID, api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the ScheduledTask object and set to run now
    const scheduledTask = new api.ScheduledTask();
    scheduledTask.runNow = true;

    // Modify the scheduled task on Deep Security Manager
    const scheduledTasksApi = new api.ScheduledTasksApi();
    scheduledTasksApi
      .modifyScheduledTask(scheduledTaskID, api, apiVersion)
      .then(modifiedScheduledTask => {
        resolve(modifiedScheduledTask);
      })
      .catch(error => {
        reject(error);
      });
  });
};
