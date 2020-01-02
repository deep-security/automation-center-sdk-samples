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

def create_daily_schedule_details(api, api_exception, custom_interval, start_time):
    """ Creates a ScheduleDetails object for use with a scheduled task for daily execution using a custom interval.

    :param api: The Deep Security API modules.
    :param api_exception: The Deep Security API exception module.
    :param custom_interval: The interval between each run. For example, '2' will start a run every second day.
    :param start_time: The epoch time in milliseconds when the scheduled task first runs.
    :return: A ScheduleDetails object.
    """

    # Create a ScheduleDetails object and set the recurrence type
    daily_schedule = api.ScheduleDetails()
    daily_schedule.recurrence_type = "daily"

    # Specify when the task runs
    daily_schedule_parameters = api.DailyScheduleParameters()

    # Use a custom frequency type to run the task at daily intervals.
    # Every day and only weekdays are other available frequency types.
    daily_schedule_parameters.frequency_type = "custom"
    daily_schedule_parameters.custom_interval = custom_interval
    daily_schedule_parameters.start_time = start_time

    # Add the schedule parameters to the schedule details
    daily_schedule.daily_schedule_parameters = daily_schedule_parameters

    return daily_schedule


def create_quarterly_schedule_details(api, api_exception, day):
    """ Creates a ScheduleDetails object for use with a scheduled task for quarterly execution (every 3 months).

    :param api: The Deep Security API modules.
    :param api_exception: The Deep Security API exception module.
    :param day: The day of the month on which the scheduled task runs.
    :return: A ScheduleDetails object.
    """

    # Create a ScheduleDetails object and set the recurrence type
    quarterly_schedule = api.ScheduleDetails()
    quarterly_schedule.recurrence_type = "monthly"

    # Specify when the task runs
    monthly_schedule_parameters = api.MonthlyScheduleParameters()

    # Set the schedule to run on a specific day of the month.
    # Other options are the last day of the month, or a specific weekday of a specific week
    monthly_schedule_parameters.frequency_type = "day-of-month"

    # Set the day
    monthly_schedule_parameters.day_of_month = day

    # Set the months to be quarterly
    monthly_schedule_parameters.months = ["january", "april", "july", "october"]

    # Add the schedule parameters to the schedule details
    quarterly_schedule.monthly_schedule_parameters = monthly_schedule_parameters

    return quarterly_schedule


def create_discover_computers_scheduled_task(api, configuration, api_version, api_exception):
    """ Creates a scheduled task that runs daily to discover new computers on the network.
        The task does not run now.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: The ID of the scheduled task.
    """

    # Create the ScheduledTask object and set the name and type. Do not run now.
    discover_computer_task = api.ScheduledTask()
    discover_computer_task.name = "Discover Computers - Daily"
    discover_computer_task.type = "discover-computers"
    discover_computer_task.run_now = False

    # Call the createDailyScheduleDetails method to obtain a daily ScheduleDetails object.
    # Set the start time to 03:00 DST.
    discover_computer_task.schedule_details = create_daily_schedule_details(api, api_exception, 2, 1536030000000);

    # Create a DiscoverComputersTaskParameters object.
    # The scan applies to a range of IP addresses, and scans discovered computers for open ports.
    task_parameters = api.DiscoverComputersTaskParameters()
    task_parameters.discovery_type = "range"
    task_parameters.iprange_low = "192.168.60.0"
    task_parameters.iprange_high = "192.168.60.255"
    task_parameters.scan_discovered_computers = True
    discover_computer_task.discover_computers_task_parameters = task_parameters

    # Create the scheduled task on Deep Security Manager
    scheduled_tasks_api = api.ScheduledTasksApi(api.ApiClient(configuration))
    scheduled_task = scheduled_tasks_api.create_scheduled_task(discover_computer_task, api_version)

    return scheduled_task.id


def check_for_security_updates_using_scheduled_task(api, configuration, api_version, api_exception):
    """ Creates a scheduled task that checks for security updates.
        The scheduled task runs immediately after it is created, and is deleted thereafter.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: The ID of the scheduled task.
    """


    # Set the name and task type
    check_for_security_updates = api.ScheduledTask()
    check_for_security_updates.name = "Check For Security Updates"
    check_for_security_updates.type = "check-for-security-updates"

    # Run when the scheduled task is created
    check_for_security_updates.run_now = True

    # Use a once-only recurrence
    schedule_details = api.ScheduleDetails()
    schedule_details.recurrence_type = 'none'

    # Set the recurrence count to 1 so that the task is deleted after running
    schedule_details.recurrence_count = 1
    schedule_parameters = api.OnceOnlyScheduleParameters()

    # The start time is not important because it is deleted after running
    schedule_parameters.start_time = 0
    schedule_details.once_only_schedule_parameters = schedule_parameters
    check_for_security_updates.schedule_details = schedule_details

    # Scan all computers
    computer_filter = api.ComputerFilter()
    computer_filter.type = "all-computers"

    # Create the task parameters object and add the computer filter
    task_parameters = api.CheckForSecurityUpdatesTaskParameters()
    task_parameters.computer_filter = computer_filter

    check_for_security_updates.check_for_security_updates_task_parameters = task_parameters

    # Create the scheduled task on Deep Security Manager
    scheduled_tasks_api = api.ScheduledTasksApi(api.ApiClient(configuration))
    scheduled_task = scheduled_tasks_api.create_scheduled_task(check_for_security_updates, api_version)

    return scheduled_task.id


def run_scheduled_task(api, configuration, api_version, api_exception, scheduled_task_id):
    """ Runs a scheduled task.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param scheduled_task_id: The ID of the scheduled task.
    :return: The modified ScheduledTasksApi object.
    """

    # Create the ScheduledTask object and set to run now
    scheduled_task = api.ScheduledTask()
    scheduled_task.run_now = True

    # Modify the scheduled task on Deep Security Manager
    scheduled_tasks_api = api.ScheduledTasksApi(api.ApiClient(configuration))

    return scheduled_tasks_api.modify_scheduled_task(scheduled_task_id, scheduled_task, api_version)
