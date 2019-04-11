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

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the DSM URL and API key from a JSON file
import json

property_file = os.path.dirname(os.path.abspath(__file__)) + '/properties.json'

with open(property_file) as raw_properties:
    properties = json.load(raw_properties)

secret_key = properties['secretkey']
url =  properties['url']


# Add DSM host information to the API client configuration
configuration = api.Configuration()
configuration.host = url
configuration.api_key['api-secret-key'] = secret_key

api_version = 'v1'

# Import code example files for testing
import anti_malware_examples
import api_key_examples
import application_control_examples
import automate_deployment_examples
import common_objects_examples
import computer_status_examples
import firewall_examples
import first_steps_get_examples
import first_steps_post_examples
import integrity_monitoring_examples
import intrusion_prevention_examples
import log_inspection_examples
import policy_examples
import search_examples
import web_reputation_examples
import tenant_examples
import settings_examples
import computer_override_examples
import scheduled_task_examples
import role_examples

# Values for use in examples

# policy_id for Application Control example
# policy_id for Integrity Monitoring example
# policy_id for Intrusion Prevention examples
# policy_id for Log Inspection Examples
# policy_id for Web Reputation examples
# policy_id for Anti-malware example
# policy_id for Firewall example
# policy_id for Search Examples
policy_id = 10

# computer_id & policy_name for Policy examples
computer_id = 1
policy_name = "API_Test_Policy"
reset_li_policy_id = 8
reset_li_rule_id = 20

# im_rule_ids for Integrity Monitoring example
im_rule_ids = [1, 2]

# li_rules for Log Inspection Examples
li_rules = [54, 55, 56]

# security_level for Web Reputation examples
security_level = "High"

# real_time_scan_config_id & real_time_scan_schedule_id for Anti-malware example
real_time_scan_config_id = 1
real_time_scan_schedule_id = 4

# key_id & role_id & key_name for API Key examples
key_id = 4
role_id = 1
key_name = "auditor_key"

# num_days & relay_list_id & name for Search Examples
num_days = 40
relay_list_id = 1
name = "API Policy"

# computer_id_status_change, rule_id, rule_id_2 & cve_id for Computer Status examples
computer_id_status_change = 36
rule_id = 6104
rule_id_2 = 5930
cve_id = "CVE-2016-7214"

# for Common Objects examples
scan_config_id = 2
dir_list_id = 1
li_rule_name = "Inspect log for error"
path = "C:/logfile.log"
pattern = "^ERROR"
group = "Windows Rules"
xml = "PGdyb3VwIG5hbWU9IldpbmRvd3MgUnVsZXMiPg0KICA8cnVsZSBpZD0iMTAwMDAwIiBsZXZlbD0iMCI"
dir_list_name = "test list"
dir_path = "C:\\windows\\"

# for Tenant examples
account_name = "Test_tenant"
tenant_id = 6
new_policy = api.Policy()
new_policy.name = "Test Policy"
new_policy.description = "Inherits from Base Policy"
new_policy.auto_requires_update = "on"
new_policy.parent_id = 1

# For Settings examples
settings_policy_id = 9

# For Computer Overrides examples
override_computer_id = 3

# For Scheduled Tasks examples
custom_interval = 2
start_time = 30000
day = 14
scheduled_task_id = 5

# For Role examples
role_name = "Auditor"

# For Automate Deployment examples
host_name = "testhostname"

def main():
    
    # Role examples
    print(
        "Displaying results from role_examples.search_roles_by_name:\n" +
        str(role_examples.search_roles_by_name(
            api, configuration, api_version, api_exception, role_name))
    )

    print(
        "Displaying results from role_examples.create_role_for_computer_reports:\n" +
        str(role_examples.create_role_for_computer_reports(
            api, configuration, api_version, api_exception))
    )

    # Scheduled Task examples
    print(
        "Displaying results from scheduled_task_examples.create_daily_schedule_details:\n" +
        str(scheduled_task_examples.create_daily_schedule_details(
            api, api_exception, custom_interval, start_time))
    )

    print(
        "Displaying results from scheduled_task_examples.create_quarterly_schedule_details:\n" +
        str(scheduled_task_examples.create_quarterly_schedule_details(
            api, api_exception, day))
    )

    print(
        "Displaying results from scheduled_task_examples.create_discover_computers_scheduled_task:\n" +
        str(scheduled_task_examples.create_discover_computers_scheduled_task(
            api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from scheduled_task_examples.check_for_security_updates_using_scheduled_task:\n" +
        str(scheduled_task_examples.check_for_security_updates_using_scheduled_task(
            api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from scheduled_task_examples.run_scheduled_task:\n" +
        str(scheduled_task_examples.run_scheduled_task(
            api, configuration, api_version, api_exception, scheduled_task_id))
    )

    # Computer Overrides examples
    print(
        "Displaying results from computer_override_examples.override_reconnaissance_scan:\n" +
        str(computer_override_examples.override_reconnaissance_scan(
            api, configuration, api_version, api_exception, override_computer_id))
    )

    print(
        "Displaying results from computer_override_examples.get_computer_overrides:\n" +
        str(computer_override_examples.get_computer_overrides(
            api, configuration, api_version, api_exception, override_computer_id))
    )

    # Settings examples
    print(
        "Displaying results from settings_examples.get_network_engine_mode:\n" +
        str(settings_examples.get_network_engine_mode(
            api, configuration, api_version, api_exception, settings_policy_id))
    )

    print(
        "Displaying results from settings_examples.set_network_engine_mode:\n" +
        str(settings_examples.set_network_engine_mode_to_inline(
            api, configuration, api_version, api_exception, settings_policy_id))
    )

    # Application Control example
    print(
        "Displaying results from application_control_examples.configure_application_control:\n" +
        str(application_control_examples.configure_application_control(
            api, configuration, api_version, api_exception, policy_id))
    )

    # Automate Deployment examples
    print(
        "Displaying results from automate_deployment_examples.configure_system_settings:\n" +
        str(automate_deployment_examples.configure_system_settings(
            api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from automate_deployment_examples.create_computer:\n" +
        str(automate_deployment_examples.add_computer(
            api, configuration, api_version, api_exception, host_name
        ))
    )

    print(
        "Displaying results from automate_deployment_examples.get_agent_deployment_script:\n" +
        automate_deployment_examples.get_agent_deployment_script(
            api, configuration, api_version, api_exception, "linux"
        )
    )

    # Policy examples
    print(
        "Displaying results from policy_examples.create_policy:\n" +
        str(policy_examples.create_policy(
            api, configuration, api_version, api_exception, policy_name))
    )

    print(
        "Displaying results from policy_examples.assign_linux_server_policy:\n" +
        str(policy_examples.assign_linux_server_policy(
            api, configuration, api_version, api_exception, computer_id))
    )

    print(
        "Displaying results from policy_examples.selective_reset_for_log_inspection_rule_on_policy:\n" +
        str(policy_examples.selective_reset_for_log_inspection_rule_on_policy(
            api, configuration, api_version, api_exception, reset_li_policy_id, reset_li_rule_id))
    )

    # Integrity Monitoring example
    print(
        "Displaying results from integrity_monitoring_examples.configure_integrity_monitoring:\n" +
        str(integrity_monitoring_examples.configure_integrity_monitoring(
            api, configuration, api_version, api_exception, policy_id, im_rule_ids))
    )

    # Intrusion Prevention examples
    print(
        "Displaying results from intrusion_prevention_examples.modify_intrusion_prevention_policy:\n" +
        str(intrusion_prevention_examples.modify_intrusion_prevention_policy(
            api, configuration, api_version, api_exception, policy_id))
    )

    print(
        "Displaying results from intrusion_prevention_examples.get_assigned_intrusion_prevention_rules:\n" +
        str(intrusion_prevention_examples.get_assigned_intrusion_prevention_rules(
            api, configuration, api_version, api_exception))
    )

    # Log Inspection Examples
    print(
        "Displaying results from log_inspection_examples.configure_log_inspection:\n" +
        str(log_inspection_examples.configure_log_inspection(
            api, configuration, api_version, api_exception, policy_id, li_rules))
    )

    # Web Reputation examples
    print(
        "Displaying results from web_reputation_examples.configure_web_reputation:\n" +
        str(web_reputation_examples.configure_web_reputation(
            api, configuration, api_version, api_exception, policy_id, security_level))
    )

    # Anti-Malware example
    print(
        "Displaying results from anti_malware_examples.modify_anti_malware_policy:\n" +
        str(anti_malware_examples.modify_anti_malware_policy(
            api, configuration, api_version, api_exception, policy_id, real_time_scan_config_id, real_time_scan_schedule_id))
    )

    # API Key examples
    print(
        "Displaying results from api__key_examples.create_audit_key:\n" +
        str(api_key_examples.create_audit_key(
            api, configuration, api_version, api_exception, key_name))
    )

    print(
        "Displaying results from api_key_examples.reset_key_secret:\n" +
        str(api_key_examples.reset_key_secret(
            api, configuration, api_version, api_exception, key_id))
    )

    print(
        "Displaying results from api_key_examples.modify_key_role:\n" +
        str(api_key_examples.modify_key_role(
            api, configuration, api_version, api_exception, key_id, role_id))
    )

    # Firewall example
    print(
        "Displaying results from firewall_examples.modify_firewall_policy:\n" +
        str(firewall_examples.modify_firewall_policy(
            api, configuration, api_version, api_exception, policy_id))
    )

    # First Steps Post example
    print(
        "Displaying results from first_steps_post_examples.search_firewall_rules:\n" +
        str(first_steps_post_examples.search_firewall_rules(
            api, configuration, api_version, api_exception))
    )

    # Search examples
    print(
        "Displaying results from search_examples.search_policies_by_name:\n" +
        str(search_examples.search_policies_by_name(
            api, configuration, api_version, api_exception, name))
    )

    print(
        "Displaying results from search_examples.search_updated_intrusion_prevention_rules:\n" +
        str(search_examples.search_updated_intrusion_prevention_rules(
            api, configuration, api_version, api_exception, num_days))
    )

    print(
        "Displaying results from search_examples.paged_search_computers:\n" +
        str(search_examples.paged_search_computers(
            api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from search_examples.get_computers_with_policy_and_relay_list:\n" +
        str(search_examples.get_computers_with_policy_and_relay_list(
            api, configuration, api_version, api_exception, relay_list_id, policy_id))
    )

    # Computer Status examples
    print(
        "Displaying results from computer_status_examples.check_anti_malware:\n" +
        str(computer_status_examples.check_anti_malware(
            api, configuration, api_version, api_exception, computer_id_status_change))
    )

    print(
        "Displaying results from computer_status_examples.find_rules_for_cve:\n" +
        str(computer_status_examples.find_rules_for_cve(
            api, configuration, api_version, api_exception, cve_id))
    )

    print(
        "Displaying results from computer_status_examples.check_computers_for_ip_rule:\n" +
        str(computer_status_examples.check_computers_for_ip_rule(
            api, configuration, api_version, api_exception, rule_id))
    )

    print(
        "Displaying results from computer_status_examples.apply_rule_to_policies:\n" +
        str(computer_status_examples.apply_rule_to_policies(
            api, configuration, api_version, api_exception, computer_status_examples.check_computers_for_ip_rule(
            api, configuration, api_version, api_exception, rule_id), rule_id_2))
    )

    print(
        "Displaying results from computer_status_examples.get_intrusion_prevention_recommendations:\n" +
        str(computer_status_examples.get_intrusion_prevention_recommendations(
            api, configuration, api_version, api_exception,
            computer_id_status_change))
    )

    print(
        "Displaying results from computer_status_examples.get_computer_statuses:\n" +
        str(computer_status_examples.get_computer_statuses(
        api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from computer_status_examples.get_anti_malware_status_for_computers:\n" +
        str(computer_status_examples.get_anti_malware_status_for_computers(
        api, configuration, api_version, api_exception))
    )

    # Common Objects examples
    print(
        "Displaying results from common_objects_examples.create_log_inspection_rule:\n" +
        str(common_objects_examples.create_log_inspection_rule(
            api, configuration, api_version, api_exception, li_rule_name, path, pattern, group))
    )

    print(
        "Displaying results from common_objects_examples.create_log_inspection_rule_xml:\n" +
        str(common_objects_examples.create_log_inspection_rule_xml(
            api, configuration, api_version, api_exception, li_rule_name, xml))
    )

    print(
        "Displaying results from common_objects_examples.add_item_to_directory_list:\n" +
        str(common_objects_examples.add_item_to_directory_list(
            api, configuration, api_version, api_exception, dir_list_name, dir_path))
    )

    print(
        "Displaying results from common_objects_examples.set_exclusion_dir_real_time_scan:\n" +
        str(common_objects_examples.set_exclusion_dir_real_time_scan(
            api, configuration, api_version, api_exception, scan_config_id, dir_list_id))
    )

    print(
        "Displaying results from common_objects_examples.create_business_hours_schedule:\n" +
        str(common_objects_examples.create_business_hours_schedule(
            api, configuration, api_version, api_exception))
    )

    # Tenant examples
    print(
        "Displaying results from tenant_examples.create_tenant:\n" +
        str(tenant_examples.create_tenant(
            api, configuration, api_version, api_exception, account_name))
    )

    print(
        "Displaying results from tenant_examples.get_ip_states_for_tenant:\n" +
        str(tenant_examples.get_ip_states_for_tenant(
            api, configuration, api_version, api_exception, tenant_id))
    )

    print(
        "Displaying results from tenant_examples.get_ip_rules_for_tenant_computers:\n" +
        str(tenant_examples.get_ip_rules_for_tenant_computers(
            api, configuration, api_version, api_exception))
    )

    print(
        "Displaying results from tenant_examples.get_tenant_rules:\n" +
        str(tenant_examples.get_tenant_rules(
            api, configuration, api_version, api_exception, tenant_id))
    )

    print(
        "Displaying results from tenant_examples.add_policy_to_tenant:\n" +
        str(tenant_examples.add_policy_to_tenant(
            api, configuration, api_version, api_exception, new_policy, tenant_id))
    )

    # First Steps Get example
    print(
        "Displaying results from first_steps_get_examples.get_policies_list:\n" +
        str(first_steps_get_examples.get_policies_list(
            api, configuration, api_version, api_exception))
    )

if __name__ == '__main__':
    main()