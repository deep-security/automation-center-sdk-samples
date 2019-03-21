# Copyright 2019 Trend Micro.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

def create_log_inspection_rule(api, configuration, api_version, api_exception, name, path, pattern, group):
    """ Creates a basic log inspection rule that monitors a log file for errors.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param name: The name for the rule.
    :param path: The path of the log file to monitor.
    :param pattern: The pattern in the file to match.
    :param group: The rule group.
    :return: A LogInspectionRulesApi object with the new rule.
    """

    # Create the rule object
    li_rule = api.LogInspectionRule()
    li_rule.name = name
    li_rule.description = "A log inspection rule"

    # Create a log file and add it to the rule
    log_file = api.LogFile()
    log_file.location = "C/logfile.log"
    log_file.format = "eventlog"
    log_files = api.LogFiles()
    log_files.log_files = [log_file]
    li_rule.log_files = log_files

    # Define the rule
    li_rule.template ="basic-rule"
    li_rule.pattern = pattern
    li_rule.pattern_type = "string"
    li_rule.rule_description = "Rule for " + path + " and pattern " + pattern
    li_rule.groups = [group]

    try:
        # Add the rule to Deep Security Manager
        log_inspection_rules_api = api.LogInspectionRulesApi(api.ApiClient(configuration))
        return log_inspection_rules_api.create_log_inspection_rule(li_rule, api_version)

    except api_exception as e:
        return "Exception: " + str(e)



def create_log_inspection_rule_xml(api, configuration, api_version, api_exception, name, xml):
    """ Creates a log inspection rule from XML that monitors a log file for errors.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param name: The name for the rule.
    :param path: The path of the log file to monitor.
    :param xml: The rule in XML format (base64-encoded).
    :return:
    """

    # Create the rule object
    li_rule = api.LogInspectionRule()
    li_rule.name = name
    li_rule.description = "A log inspection rule"

    # Create a log file and add it to the rule
    log_file = api.LogFile()
    log_file.location = "C/logfile.log"
    log_file.format = "eventlog"
    log_files = api.LogFiles()
    log_files.log_files = [log_file]
    li_rule.log_files = log_files

    # Define the rule
    li_rule.template ="custom"
    li_rule.XML = xml

    try:
        # Add the rule to Deep Security Manager
        log_inspection_rules_api = api.LogInspectionRulesApi(api.ApiClient(configuration))
        return log_inspection_rules_api.create_log_inspection_rule(li_rule, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def add_item_to_directory_list(api, configuration, api_version, api_exception, dir_list_name, dir_path):
    """ Adds a directory to a directory list. If the list does not exist, it is created.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param dir_list_name: The name of the directory list.
    :param dir_path: The path to add to the directory list.
    :return: A DirectoryListsApi object that contains the added directory list.
    """

    dir_list = api.DirectoryList()
    dir_lists_api = api.DirectoryListsApi(api.ApiClient(configuration))

    try:
        dir_lists = dir_lists_api.list_directory_lists(api_version)

        for dir in dir_lists.directory_lists:
            if dir.name == dir_list_name:
                dir_list.dir_list = dir

        # Create the directory list if dir_list_name was not found
        if dir_list.name == None:
            dir_list.name = dir_list_name
            dir_list = dir_lists_api.create_directory_list(dir_list, api_version)

        dir_list_with_directory = api.DirectoryList()
        dir_list_with_directory.items = dir_path

        return dir_lists_api.modify_directory_list(dir_list.id, dir_list_with_directory, api_version)

    except api_exception as e:
        return "Exception: " + str(e)

def set_exclusion_dir_real_time_scan(api, configuration, api_version, api_exception, scan_config_id, dir_list_id):
    """ Configures a Malware Scan Configuration to exclude a directory list from scans.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param scan_config_id: The ID of the scan configuration.
    :param dir_list_id: The ID of the directory list to exclude from scans.
    :return: An AntiMalwareConfigurationsApi object with the modified scan configuration.
    """

    # Create an anti-malware scan configuration
    real_time_config = api.AntiMalwareConfiguration()

    # Set the exclusion
    real_time_config.excluded_directory_list_id = dir_list_id

    try:
        # Modify the anti-malware scan configuration on Deep Security Manager
        am_configurations_api = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
        return am_configurations_api.modify_anti_malware(scan_config_id, real_time_config, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def create_business_hours_schedule(api, configuration, api_version, api_exception):
    """ Creates a schedule for an activity that occurs during normal business hours.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A SchedulesApi object with the business hours schedule.
    """

    hours = []

    for day in range(0, 7):
        if day != 0 or day != 6:
            for hour in range(0, 24):
                if hour > 8 or hour > 17:
                    hours.append(True)
                else:
                    hours.append(False)
        else:
            for hour in range(0, 24):
                hours.append(False)

    # Create the schedule
    schedule = api.Schedule()
    schedule.name = "Normal Business Hours"
    schedule.hours_of_week = hours

    try:
        # Add the schedule to Deep Security Manager
        schedules_api = api.SchedulesApi(api.ApiClient(configuration))
        return schedules_api.create_schedule(schedule, api_version)

    except api_exception as e:
        return "Exception: " + str(e)