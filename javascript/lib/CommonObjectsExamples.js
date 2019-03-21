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
 * Creates a basic log inspection rule that monitors a log file for errors.
 * @param {Object} api The Deep Security API modules.
 * @param {String} name The name for the rule.
 * @param {String} path The path of the log file to monitor.
 * @param {String} pattern The pattern in the file to match.
 * @param {String} group The rule group.
 * @param {String} apiVersion The version of the API to use.
 * @return {Promise} A promise that contains the rule.
 */
exports.createLogInspectionRule = function(api, name, path, pattern, group, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the rule object and set name
    const liRule = new api.LogInspectionRule();
    liRule.name = name;

    // Create the LogFile and add to rule
    const logFile = new api.LogFile();
    logFile.location = path;
    logFile.format = "eventlog";
    const logFiles = new api.LogFiles();
    logFiles.logFiles = [logFile];
    liRule.logFiles = logFiles;

    // Define the rule
    liRule.template = "basic-rule";
    liRule.pattern = pattern;
    liRule.patternType = "string";
    liRule.ruleDescription = "Rule for " + path + " and pattern " + pattern;
    liRule.groups = [group];

    // Creates on Deep Security Manager
    const createRule = () => {
      const logInspectionRulesApi = new api.LogInspectionRulesApi();
      return logInspectionRulesApi.createLogInspectionRule(liRule, apiVersion);
    };

    createRule()
      .then(data => {
        resolve(data);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Creates a log inspection rule from XML that monitors a log file for errors.
 * @param {Object} api The Deep Security API modules.
 * @param {String} name The name for the rule.
 * @param {String} path The path of the log file to monitor.
 * @param {String} xml  The rule in XML format (base64-encoded).
 * @param {String} apiVersion The version of the API to use.
 * @return {Promise} A promise that contains the rule.
 */
exports.createLogInspectionRuleXML = function(api, name, path, xml, apiVersion) {
  return new Promise(function(resolve, reject) {
    // Create the rule object and set name
    const liRule = new api.LogInspectionRule();
    liRule.name = name;

    // Create the LogFile and add to rule
    const logFile = new api.LogFile();
    logFile.location = path;
    logFile.format = "eventlog";
    const logFiles = new api.LogFiles();
    logFiles.logFiles = [logFile];
    liRule.logFiles = logFiles;

    // Define the rule
    liRule.template = "custom";
    liRule.ruleXML = xml;

    // Creates the rule on Deep Security Manager
    const createRule = function() {
      const logInspectionRulesApi = new api.LogInspectionRulesApi();
      return logInspectionRulesApi.createLogInspectionRule(liRule, apiVersion);
    };

    createRule()
      .then(data => {
        resolve(data);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Adds a directory to a directory list.
 * @param {object} api The api module.
 * @param {String} dirListID The ID of the directory list.
 * @param {String} dirPath The path to add to the directory list.
 * @param {String} apiVersion The api version to use.
 * @return {Promise} A Promise that contains the directory list.
 */
exports.addItemToDirectoryList = function(api, dirListID, dirPath, apiVersion) {
  return new Promise((resolve, reject) => {
    getDirList(api, dirListID, apiVersion) // Get the list
      .then(dirList => addDirPath(api, dirList, dirPath, apiVersion)) // Add the path to the list
      .then(data => {
        resolve(data); // Return the response from the addDirPath call
      })
      .catch(error => {
        reject(error);
      });
  });
};

// PRIVATE METHODS //
// Gets a directory list
function getDirList(api, dirListID, apiVersion) {
  const directoryListsApi = new api.DirectoryListsApi();
  return directoryListsApi.describeDirectoryList(dirListID, apiVersion);
}

// Adds a path to a directory list
function addDirPath(api, list, dirPath, apiVersion) {
  // Verify that we have the listID
  try {
    if (!list.ID) {
      throw { error: true, message: "Directory list ID is required" };
    }
  } catch (error) {
    return error;
  }

  // Add the path to the list object
  const dirList = new api.DirectoryList();
  dirList.items = list.items;
  dirList.items.push(dirPath);

  // Add the path to the list on Deep Security Manager
  const directoryListsApi = new api.DirectoryListsApi();
  return directoryListsApi.modifyDirectoryList(list.ID, dirList, apiVersion);
}

/*
 * Configures a Malware Scan Configuration to exclude a directory list from scans.
 * @param {object} api The API module.
 * @param {Number} dirListID The ID of the directory list to exclude from scans.
 * @param {Number} scanConfigID The ID of the scan configuration.
 * @param {String} apiVersion The version of the API to use.
 * @return {Promise} A promise that contains the malware scan configuration ID.
 */
exports.setExclusionDirRealTimeScan = function(api, dirListID, scanConfigID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create a malware scan configuration
    const realtimeConfig = new api.AntiMalwareConfiguration();

    // Set the exclusion
    realtimeConfig.excludedDirectoryListID = dirListID;

    // Modify the scan configuration on Deep Security Manager
    const amConfigurationsApi = new api.AntiMalwareConfigurationsApi();
    amConfigurationsApi
      .modifyAntiMalware(scanConfigID, realtimeConfig, apiVersion)
      .then(scanConfig => {
        resolve(scanConfig.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Creates a schedule for an activity that occurs during normal business hours.
 * @param {object} api The API module.
 * @param {String} apiVersion The version of the API to use.
 * @return {Promise} A promise that contains the schedule ID.
 */
exports.createBusinessHoursSchedule = function(api, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create the array of boolean values that represent hours of the week
    const hours = [];
    for (let i = 0; i < 7; i++) {
      if (i !== 0 && i !== 6) {
        //true from Monday - Friday
        for (let j = 0; j < 24; j++) {
          if (j > 8 && j < 17) {
            //true from 9AM to 5PM
            hours.push(true);
          } else {
            hours.push(false);
          }
        }
      } else {
        //false for weekends
        for (let k = 0; k < 24; k++) {
          hours.push(false);
        }
      }
    }

    // Create the schedule
    const schedule = new api.Schedule();
    schedule.name = "Normal Business Hours";
    schedule.hoursOfWeek = hours;

    // Add to Deep Security Manager
    const schedulesApi = new api.SchedulesApi();
    schedulesApi
      .createSchedule(schedule, apiVersion)
      .then(newSchedule => {
        resolve(newSchedule.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
