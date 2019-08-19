/*
 * Copyright 2019 Trend Micro and contributors.
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
 * This Node.js app runs the JavaScript examples that are defined in the module files (lib folder).
 * NOTE: Some examples will make changes to your Deep Security Manager!
 *
 * It is not guaranteed that all examples are executed.
 */

const api = require("@trendmicro/deepsecurity");
const fs = require("fs");

// Get the DSM URL and API key from the properties.json file
const rawProperties = fs.readFileSync("./properties.json");
const properties = JSON.parse(rawProperties);

// Configure ApiClient
let defaultClient = api.ApiClient.instance;
defaultClient.basePath = properties.url;
let DefaultAuthentication = defaultClient.authentications["DefaultAuthentication"];
DefaultAuthentication.apiKey = properties.secretkey;

//Uncomment to allow connections that are 'secured' with self-signed certificate
//process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

//Environment values -- change as needed
let auditorRoleId = 2;
let computerID = 2;
let policyID = 1;
let realTimeScanConfigID = 1;
let directoryListID = 1;

// The version of the API we're using
const apiVersion = "v1";

// ### First Steps Examples ###
const FirstStepsGetExample = require("./lib/FirstStepsGetExample.js");
const FirstStepsPostExample = require("./lib/FirstStepsPostExample.js");

FirstStepsGetExample.getPolicies(properties.url, properties.secretkey)
  .then(policies => {
    console.log(`Obtained ${policies.policies.length} policies`);
  })
  .catch(error => {
    console.log(`Error getting policies: ${error}`);
  });

// Replace arguments with actual values
FirstStepsPostExample.searchFirewallRules(properties.url, properties.secretkey)
  .then(firewallRules => {
    console.log(`Obtained the following firewall rules:\n`);
    for (let i in firewallRules) {
      console.log(`${firewallRules[i].ID} ${firewallRules[i].name}\n`);
    }
  })
  .catch(error => {
    console.log(`Error searching for Firewall rules: ${error}`);
  });

/*
// ### API Rate Limit examples ###
const RateLimitExamples = require("./lib/RateLimitExamples.js");

// IDs of computers to modify; computerIDs.length > an API rate limit -- edit for your environment
const computerIDs = [31, 32, 33, 34, 35];
RateLimitExamples.setComputerPolicyAndCheckRateLimits(computerIDs, policyID, api, apiVersion)
  .then(modifiedComputerIDs => {
    console.log(`Modified computers: ${modifiedComputerIDs}`);
  })
  .catch(error => {
    console.log(error);
  });
*/
/*
// ### Roles examples ###
const RoleExamples = require("./lib/RolesExamples.js");

RoleExamples.searchRolesByName("Auditor", api, apiVersion)
  .then(roleID => {
    console.log(`Found role with ID: ${roleID}`);
  })
  .catch(error => {
    console.log(`Error searching for roles: ${error}`);
  });

RoleExamples.createRoleForComputerReports(api, apiVersion)
  .then(roleID => {
    console.log(`Created role with ID: ${roleID}`);
  })
  .catch(error => {
    console.log(`Error creating role: ${error}`);
  });
*/
/*
// ### API Key examples ###
const ApiKeyExamples = require("./lib/ApiKeyExamples.js");

ApiKeyExamples.createAuditKey(api, "test key", apiVersion)
  .then(auditKeyID => {
    keyID = auditKeyID;
    console.log(`Created key with ID: ${auditKeyID}`);
    return ApiKeyExamples.resetKeySecret(api, keyID, apiVersion);
  })
  .then(keySecret => {
    console.log(`New key secret: ${keySecret}`);
    return ApiKeyExamples.modifyKeyRole(api, keyID, auditorRoleId, apiVersion);
  })
  .then(roleID => {
    console.log(`Key of ID ${keyID} is assigned role of ID: ${roleID}`);
  })
  .catch(error => {
    console.log(`Error running API Key examples: ${error}`);
  });
*/
/*
// ### Scheduled Task examples ###
const ScheduledTaskExamples = require("./lib/ScheduledTaskExamples.js");

console.log(
  `Created daily schedule: ${JSON.stringify(ScheduledTaskExamples.createDailyScheduleDetails(2, 30000, api), null, 4)}`
);
console.log(
  `Created quarterly schedule: ${JSON.stringify(
    ScheduledTaskExamples.createQuarterlyScheduleDetails(14, api),
    null,
    4
  )}`
);

let scheduledTaskID;
ScheduledTaskExamples.createDiscoverComputersScheduledTask(api, apiVersion)
  .then(stID => {
    console.log(`Created discover computers scheduled task ${stID}`);
    return ScheduledTaskExamples.runScheduledTask(stID, api, apiVersion);
  })
  .then(stID => {
    console.log(`Ran discover computers scheduled task: ${stID}`);
    return ScheduledTaskExamples.checkForSecurityUpdatesUsingScheduledTask(api, apiVersion);
  })
  .then(stID => {
    console.log(`Created, ran, and deleted check for security updates scheduled task: ${stID}`);
  })
  .catch(error => {
    console.log(`Error running scheduled task examples: ${error}`);
  });
*/
/*
// ### Automated Deployment Examples ###
const AutomateDeploymentExamples = require("./lib/AutomateDeploymentExamples.js");

AutomateDeploymentExamples.configureSystemSettings(api, apiVersion)
  .then(systemSettings => {
    console.log(
      `New value for platformSettingActiveSessionsMax: ${systemSettings.platformSettingActiveSessionsMax.value}`
    );
  })
  .catch(error => {
    console.log(`Error setting system setting: ${error}`);
  });

AutomateDeploymentExamples.addComputer("testcomputer", api, apiVersion)
  .then(function(data) {
    computerID = data;
    console.log(`added computer with ID: ${data}`);
  })
  .catch(error => {
    console.log(`Error adding computer: ${error}`);
  });

const platform = api.AgentDeploymentScript.PlatformEnum.linux;
AutomateDeploymentExamples.getAgentDeploymentScript(api, apiVersion, platform, null, false, true)
  .then(script => {
    console.log(script);
  })
  .catch(error => {
    console.log(error);
  });
*/
/*
// ### Policy Examples ###
const PolicyExample = require("./lib/PolicyExample.js");

PolicyExample.createPolicy(api, "Test Policy", apiVersion)
  .then(returnedPolicyID => {
    policyID = returnedPolicyID;
    console.log(`Created policy: ${returnedPolicyID}`);
  })
  .catch(error => {
    console.log(`Error creating policy: ${error}`);
  });

PolicyExample.assignLinuxServerPolicy(api, computerID, apiVersion)
  .then(modifiedComputer => {
    console.log(`Assigned Computer ${modifiedComputer.ID} with policy ${modifiedComputer.policyID}`);
  })
  .catch(error => {
    console.log(`Error assigning policy: ${error}`);
  });
*/

const CommonObjectsExamples = require("./lib/CommonObjectsExamples.js");
const ComputerStatusExamples = require("./lib/ComputerStatusExamples.js");
/*
// ### Anti-Malware Examples ###
const AntiMalwareExample = require("./lib/AntiMalwareExample.js");

CommonObjectsExamples.createBusinessHoursSchedule(api, apiVersion)
  .then(newScheduleID => {
    console.log(`Created schedule of ID: ${newScheduleID}`);
    return AntiMalwareExample.modifyAntiMalwarePolicy(api, policyID, realTimeScanConfigID, newScheduleID, apiVersion);
  })
  .then(modifiedPolicy => {
    console.log(
      `Policy ${modifiedPolicy.ID} uses realTimeScanConfiguration ${
        modifiedPolicy.antiMalware.realTimeScanConfigurationID
      }`
    );
  })
  .catch(error => {
    console.log(`Error creating schedule and using in policy: ${error}`);
  });

let directoryPath = "C:\\windows\\";
CommonObjectsExamples.addItemToDirectoryList(api, directoryListID, directoryPath, apiVersion)
  .then(modifiedDirectoryList => {
    console.log(`Modified directory list members: ${modifiedDirectoryList}`);
  })
  .catch(error => {
    console.log(`Error adding item to directory list: ${error}`);
  });

CommonObjectsExamples.setExclusionDirRealTimeScan(api, directoryListID, realTimeScanConfigID, apiVersion)
  .then(scanConfigID => {
    console.log(`Modified malware scan configuration ${scanConfigID}`);
  })
  .catch(error => {
    console.log(`Error modifying malware scan configuration: ${error}`);
  });

ComputerStatusExamples.getAntiMalwareStatusForComputers(api, apiVersion)
  .then(csv => {
    console.log(`Returned CSV text: ${csv}`);
  })
  .catch(error => {
    console.log(`Error getting Anti-Malware statuses: ${error}`);
  });

ComputerStatusExamples.checkAntiMalware(api, computerID, apiVersion)
  .then(amSettings => {
    console.log(`Computer ${computerID} has Anti-Malware settings ${JSON.stringify(amSettings, null, 4)}`);
  })
  .catch(error => {
    console.log(`Error retrieving Anti-Malware settings: ${error}`);
  });
*/
/*
// ### Firewall Examples ###
const FirewallExample = require("./lib/FirewallExample.js");
const ruleIDs = [1, 2, 3, 4];

FirewallExample.modifyFirewallPolicy(api, ruleIDs, policyID, apiVersion)
  .then(modifiedPolicyID => {
    console.log(`Modified policy ${modifiedPolicyID}.`);
  })
  .catch(error => {
    console.log(`Error setting Firewall state: ${error}`);
  });
*/
/*
// ### Web Reputation Examples ###
const WebReputationExample = require("./lib/WebReputationExample.js");

let securityLevel = 80; // Change as required
WebReputationExample.configureWebReputation(api, policyID, securityLevel, apiVersion)
  .then(modifiedPolicyID => {
    console.log(`Modified policy ${modifiedPolicyID}.`);
  })
  .catch(error => {
    console.log(`Error setting Web Reputation state: ${error}`);
  });
*/
/*
// ### Integrity Monitoring Examples ###
const IntegrityMonitoringExample = require("./lib/IntegrityMonitoringExample.js");
let imRules = [1, 2]; // Change as required

IntegrityMonitoringExample.configureIntegrityMonitoring(api, policyID, imRules, apiVersion)
  .then(modifiedPolicyID => {
    console.log(`Policy ${modifiedPolicyID} is successfully modified.`);
  })
  .catch(error => {
    console.log(`Error setting Integrity Monitoring state: ${error}`);
  });
*/
/*
// ### Log Inspection Examples ###
const LogInspectionExample = require("./lib/LogInspectionExample.js");
let liRules = [1]; // Change as required

LogInspectionExample.configureLogInspection(api, policyID, liRules, apiVersion)
  .then(modifiedPolicyID => {
    console.log(`Policy ${modifiedPolicyID} is updated.`);
  })
  .catch(error => {
    console.log(`Error setting Log Inspection state: ${error}`);
  });

// Log Inspection rule details
var params = {
  name: "Inspect log for error",
  namexml: "Inspect log for error xml",
  path: "C:/logfile.log",
  pattern: "^ERROR",
  group: "Windows Rules",
  xml:
    "PGdyb3VwIG5hbWU9IldpbmRvd3MgUnVsZXMiPg0KICA8cnVsZSBpZD0iMTAwMDAwIiBsZXZlbD0iMCI+DQogICAgPG1hdGNoPl5FUlJPUjwvbWF0Y2g+DQogICAgPGRlc2NyaXB0aW9uPlRlc3QgUnVsZSBEZXNjcmlwdGlvbjwvZGVzY3JpcHRpb24+DQogIDwvcnVsZT4NCjwvZ3JvdXA+"
};

CommonObjectsExamples.createLogInspectionRule(api, params.name, params.path, params.pattern, params.group, apiVersion)
  .then(liRule => {
    console.log(`Created Log Inspection rule: ${JSON.stringify(liRule, null, 4)}`);
  })
  .catch(error => {
    console.log(`Error creating Log Inspection rule: ${error}`);
  });

CommonObjectsExamples.createLogInspectionRuleXML(api, params.namexml, params.path, params.xml, apiVersion)
  .then(liRule => {
    console.log(`Created XML-based Log Inspection rule using: ${JSON.stringify(liRule, null, 4)}`);
  })
  .catch(error => {
    console.log(`Error creating XML-based Log Inspection rule: ${error}`);
  });
*/
/*
// ### Application Control Examples ###
const ApplicationControlExample = require("./lib/ApplicationControlExample.js");

ApplicationControlExample.configureApplicationControl(api, policyID, apiVersion)
  .then(modifiedPolicy => {
    console.log(`Policy ${modifiedPolicy.ID} has Application Control state ${modifiedPolicy.applicationControl.state}`);
  })
  .catch(error => {
    console.log(`Error setting Application Control state: ${error}`);
  });
*/
/*
// ### Intrusion Prevention Examples ###
const IntrusionPreventionExample = require("./lib/IntrusionPreventionExample.js");
const ipRuleIDs = [1, 2, 3, 4];

IntrusionPreventionExample.modifyIntrusionPreventionPolicy(api, policyID, ipRuleIDs, apiVersion)
  .then(modifiedPolicyID => {
    console.log(`Modified policy ${modifiedPolicyID}.`);
  })
  .catch(error => {
    console.log(`Error configuring Intrusion Prevention: ${error}`);
  });

IntrusionPreventionExample.getAssignedIntrusionPreventionRules(api, apiVersion)
  .then(computersAndRules => {
    console.log(`Obtained Intrusion Prevention rules for computers: \n `);
    console.log(JSON.stringify(computersAndRules, null, 4));
  })
  .catch(error => {
    console.log(`Error obtaining Intrusion Prevention rules: ${error}`);
  });

let threatID = "CVE-2016-7214";
let liRuleID;
ComputerStatusExamples.findRulesForCVE(api, threatID, apiVersion)
  .then(ruleIDs => {
    liRuleID = ruleIDs[0];
    console.log(`Rule IDs for ${threatID}: ${ruleIDs}`);
    return ComputerStatusExamples.checkComputersForIPRule(api, liRuleID, apiVersion);
  })
  .then(computerList => {
    console.log(`Vulnerable computers: \n`);
    for (let i = 0; i < computerList.length; i++) {
      console.log(`${computerList[i].ID}`);
    }
    return ComputerStatusExamples.applyRuleToPolicy(api, computerList[0], liRuleID, apiVersion);
  })
  .then(modifiedPolicy => {
    console.log(`Rules that are applied to policy: ${modifiedPolicy.intrusionPrevention.ruleIDs}`);
  })
  .catch(error => {
    console.log(`Error patching vulnerable computers: ${error}`);
  });

ComputerStatusExamples.getRecommendedIPRules(api, computerID, apiVersion)
  .then(recommendedRules => {
    console.log(`Recommended Intrusion Prevention rules: ${recommendedRules}`);
  })
  .catch(error => {
    console.log(`Error getting recommnened Intrusion Prevention rules: ${error}`);
  });
*/
/*
// ### Computer Status Examples ###

ComputerStatusExamples.getComputerStatuses(api, apiVersion)
  .then(csv => {
    console.log(`Returned CSV text: ${csv}`);
  })
  .catch(error => {
    console.log(`Error getting computer statuses: ${error}`);
  });
*/
/*
// ### Computer Override Examples ###
const ComputerOverrideExamples = require("./lib/ComputerOverrideExamples.js");

ComputerOverrideExamples.overrideReconnaissanceScan(api, computerID, apiVersion)
  .then(returnedSettings => {
    console.log(
      `ComputerSettings.firewallSettingReconnaissanceEnabled: ${
        returnedSettings.firewallSettingReconnaissanceEnabled.value
      }`
    );
  })
  .catch(error => {
    console.log(`Error setting firewallSettingReconnaissanceEnabled: ${error}`);
  });

const Options = api.Expand.OptionsEnum;
const expand = new api.Expand.Expand(Options.intrusionPrevention);

ComputerOverrideExamples.getComputerOverrides(api, expand, computerID, apiVersion)
  .then(overrides => {
    console.log(`getComputerOverrides returned: \n`);
    Object.keys(overrides).forEach(function (key, index) {
      if (overrides[key] !== undefined) console.log(`${key} = ${JSON.stringify(overrides[key])}`);
    });
  })
  .catch(error => {
    console.log(`Error getting computer overrides: ${error}`);
  });
*/
/*
// ### Settings Examples ###
const SettingsExamples = require("./lib/SettingsExamples.js");

SettingsExamples.getNetworkEngineMode(api, policyID, apiVersion)
  .then(networkEngineModeValue => {
    console.log(`Network Engine Mode value: ${networkEngineModeValue}`);
  })
  .catch(error => {
    console.log(`Error getting Network Engine Mode value:${error}`);
  });

SettingsExamples.setNetworkEngineModeToInline(api, policyID, apiVersion)
  .then(networkEngineModeValue => {
    console.log(`Changed Network Engine Mode to: ${networkEngineModeValue}`);
  })
  .catch(error => {
    console.log(`Error setting Network Engine Mode: ${error}`);
  });
*/

// ### Search Examples ###
const SearchExamples = require("./lib/SearchExamples.js");
/*
let policyName = "Base Policy";
SearchExamples.searchPoliciesByName(api, policyName, apiVersion)
  .then(searchResults => {
    console.log(`Found policy named ${searchResults.policies[0].name}`);
  })
  .catch(error => {
    console.log(`Error searching for policy: ${error}`);
  });

let relayListID = 0;
SearchExamples.getComputersWithPolicyAndRelayList(api, relayListID, policyID, apiVersion)
  .then(searchResults => {
    console.log(`Found ${searchResults.computers.length} computers`);
  })
  .catch(error => {
    console.log(`Error performing multiple-criteria search: ${error}`);
  });

let numberOfDays = 60; // Change as required
SearchExamples.searchUpdatedIntrusionPreventionRules(api, numberOfDays, apiVersion)
  .then(searchResults => {
    console.log(
      `Found ${
      searchResults.intrusionPreventionRules.length
      } rules that have been updated within the last ${numberOfDays} days`
    );
  })
  .catch(error => {
    console.log(`Error searching Intrusion Prevention rules: ${error}`);
  });

SearchExamples.pagedSearchComputers(api, apiVersion)
  .then(pages => {
    console.log(`Obtained ${pages.length} pages of computers`);
  })
  .catch(error => {
    console.log(`Error searching computers in pages: ${error}`);
  });

SearchExamples.searchComputersByAwsAccount(api, "my AWS account ID", apiVersion)
  .then(searchResults => {
    console.log(`Found ${searchResults.computers.length} computers.`);
  })
  .catch(error => {
    console.log(`Error searching Computers by AWS account: ${error}`);
  });

SearchExamples.searchComputersNotUpdated(api, apiVersion)
  .then(searchResults => {
    console.log(`Found ${searchResults.computers.length} computers that have not been udpated.`);
  })
  .catch(error => {
    console.log(`Error searching Computers by AWS account: ${error}`);
  });
*/
/*
// ### Tenant examples ###

// NOTE: Not applicable for DSaaS instances
const TenantExample = require("./lib/TenantExample.js");

let accountName = "TestAccount";
let tenantID;

TenantExample.createTenant(api, accountName, apiVersion)
  .then(newTenant => {
    tenantID = newTenant.ID;
    console.log(`Created tenant ${newTenant.ID}`);
  })
  .catch(error => {
    console.log(`Error creating tenant: ${error}`);
  });

TenantExample.getIPStatesForTenant(api, tenantID, apiVersion)
  .then(computerAndIPStates => {
    console.log(`Obtained Intrusion Prevention states for ${computerAndIPStates.length} tenant computers`);
  })
  .catch(error => {
    console.log(`Error obtaining Intrusion Prevention state for tenant computers: ${error}`);
  });

TenantExample.getIpRulesForTenantComputers(api, apiVersion, properties.secretkey)
  .then(function (tenantComputersAndRules) {
    console.log(`Obtained Intrusion Prevention rules for ${tenantComputersAndRules.length} tenants`);
  })
  .catch(function (error) {
    console.log(`Error iterating tenants to get assigned Intrusion Prevention rules: ${error}`);
  });

var newPolicy = new api.Policy();
newPolicy.name = "Test Policy";
newPolicy.description = "Inherits from Base Policy";
newPolicy.autoRequiresUpdate = api.Policy.AutoRequiresUpdateEnum.on;
newPolicy.parentID = 1;

TenantExample.addPolicyToTenant(api, newPolicy, tenantID, apiVersion)
  .then(returnedPolicy => {
    console.log(`Created policy ${returnedPolicy.ID} on tenant`);
  })
  .catch(error => {
    console.log(`Error creating policy on tenant: ${error}`);
  });
*/
