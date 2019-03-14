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

import java.util.List;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.ComputersApi;
import com.trendmicro.deepsecurity.api.GlobalRulesApi;
import com.trendmicro.deepsecurity.api.PoliciesApi;
import com.trendmicro.deepsecurity.api.RulesetsApi;
import com.trendmicro.deepsecurity.api.SoftwareChangesApi;
import com.trendmicro.deepsecurity.api.SoftwareInventoriesApi;
import com.trendmicro.deepsecurity.model.ApplicationControlComputerExtension;
import com.trendmicro.deepsecurity.model.ApplicationControlComputerExtension.MaintenanceModeStatusEnum;
import com.trendmicro.deepsecurity.model.ApplicationControlGlobalRule;
import com.trendmicro.deepsecurity.model.ApplicationControlGlobalRules;
import com.trendmicro.deepsecurity.model.ApplicationControlPolicyExtension;
import com.trendmicro.deepsecurity.model.Computer;
import com.trendmicro.deepsecurity.model.Policy;
import com.trendmicro.deepsecurity.model.Ruleset;
import com.trendmicro.deepsecurity.model.SearchCriteria;
import com.trendmicro.deepsecurity.model.SearchCriteria.NumericTestEnum;
import com.trendmicro.deepsecurity.model.SearchFilter;
import com.trendmicro.deepsecurity.model.SoftwareChange;
import com.trendmicro.deepsecurity.model.SoftwareChangeReview;
import com.trendmicro.deepsecurity.model.SoftwareChangeReview.ActionEnum;
import com.trendmicro.deepsecurity.model.SoftwareChanges;
import com.trendmicro.deepsecurity.model.SoftwareInventory;
import com.trendmicro.deepsecurity.model.SoftwareInventory.StateEnum;

/**
 * Configures the Application Control module.
 */
public class ApplicationControlExamples {
	/**
	 * Turns on the Application Control module for a policy.
	 * 
	 * @param policyId The ID of the policy to modify.
	 * @param apiVersion The API version.
	 * @throws ApiException if a problem occurs when modifying the policy on Deep Security Manager.
	 * @return The modified policy.
	 */
	public static Policy configureApplicationControl(Integer policyId, String apiVersion) throws ApiException {

		// Turn on ApplicationControl
		ApplicationControlPolicyExtension appControlPolicyExtension = new ApplicationControlPolicyExtension();
		appControlPolicyExtension.setState(ApplicationControlPolicyExtension.StateEnum.ON);

		// Configure a policy and update on Deep Security Manager
		Policy updatePolicy = new Policy();
		updatePolicy.setApplicationControl(appControlPolicyExtension);
		PoliciesApi policiesApi = new PoliciesApi();
		return policiesApi.modifyPolicy(policyId, updatePolicy, Boolean.FALSE, apiVersion);
	}

	/**
	 * Blocks all unrecognized software on a computer.
	 * 
	 * @param computerId The ID of the computer.
	 * @param apiVersion The API version.
	 * @throws ApiException if a problem occurs when searching and when blocking software changes on Deep Security Manager.
	 */
	public static SoftwareChangeReview blockComputerSoftwareChanges(Integer computerId, String apiVersion) throws ApiException {

		// Search for software changes on the computer
		// Search criteria
		SearchCriteria computerCriteria = new SearchCriteria();
		computerCriteria.setFieldName("computerID");
		computerCriteria.setNumericTest(NumericTestEnum.EQUAL);
		computerCriteria.setNumericValue(Long.valueOf(computerId.longValue()));

		// Search filter
		SearchFilter searchFilter = new SearchFilter();
		searchFilter.addSearchCriteriaItem(computerCriteria);

		// Perform the search
		SoftwareChangesApi softwareChangesApi = new SoftwareChangesApi();
		SoftwareChanges softwareChanges = softwareChangesApi.searchSoftwareChanges(searchFilter, apiVersion);

		// Block the software changes
		SoftwareChangeReview softwareChangeReview = new SoftwareChangeReview();
		softwareChangeReview.setAction(ActionEnum.BLOCK);
		for (SoftwareChange softwareChange : softwareChanges.getSoftwareChanges()) {
			softwareChangeReview.addSoftwareChangeIDsItem(softwareChange.getID());
		}
		return softwareChangesApi.reviewSoftwareChanges(softwareChangeReview, apiVersion);
	}

	/**
	 * Create a shared ruleset from a computer's software inventory.
	 * 
	 * @param computerId The ID of the computer whose software inventory the ruleset will be created from.
	 * @param rulesetName The name of the ruleset.
	 * @param apiVersion The API version.
	 * @throws ApiException if a problem occurs when creating the ruleset on Deep Security Manager.
	 * @return The newly created ruleset.
	 */
	public static Ruleset createSharedRuleset(Integer computerId, String rulesetName, String apiVersion) throws ApiException {

		// Create software inventory
		SoftwareInventory softwareInventory = new SoftwareInventory();
		softwareInventory.setComputerID(computerId);

		SoftwareInventoriesApi softwareInventoriesApi = new SoftwareInventoriesApi();

		SoftwareInventory newInventory = softwareInventoriesApi.createSoftwareInventory(softwareInventory, apiVersion);
		Long inventoryId = newInventory.getID();

		// Wait for software inventory to build
		while (!newInventory.getState().equals(StateEnum.COMPLETE)) {

			// Check status every 30 seconds
			try {
				// System.out.println("Waiting 30 seconds...");
				Thread.sleep(30000L);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			newInventory = softwareInventoriesApi.describeSoftwareInventory(inventoryId, apiVersion);
		}

		// Create shared ruleset
		Ruleset ruleset = new Ruleset();
		ruleset.setName(rulesetName);

		RulesetsApi rulesetApi = new RulesetsApi();
		return rulesetApi.createRuleset(ruleset, inventoryId, apiVersion);
	}

	/**
	 * Add new global rules.
	 * 
	 * @param sha256List The list of SHA-256 hashes to create rules for.
	 * @param apiVersion The API version.
	 * @throws ApiException if a problem occurs when adding the global rules on Deep Security Manager.
	 * @return A list of ApplicationControlGlobalRule objects.
	 */
	public static ApplicationControlGlobalRules addGlobalRules(List<String> sha256List, String apiVersion) throws ApiException {

		// Create global rules
		ApplicationControlGlobalRules globalRules = new ApplicationControlGlobalRules();
		for (String sha256 : sha256List) {
			ApplicationControlGlobalRule globalRule = new ApplicationControlGlobalRule();
			globalRule.setSha256(sha256);
			globalRules.addApplicationControlGlobalRulesItem(globalRule);
		}

		// Add the global rules
		GlobalRulesApi globalRulesApi = new GlobalRulesApi();
		return globalRulesApi.addGlobalRules(globalRules, apiVersion);
	}

	/**
	 * Turn on maintenance mode on a computer.
	 * 
	 * @param computerId The ID number of the computer.
	 * @param duration The duration of the maintenance mode in milliseconds.
	 * @param apiVersion The API version.
	 * @return The modified computer.
	 */
	public static Computer turnOnMaintenanceMode(Integer computerId, Integer duration, String apiVersion) throws ApiException {

		// Create and configure an ApplicationControlComputerExtension
		ApplicationControlComputerExtension applicationControl = new ApplicationControlComputerExtension();
		applicationControl.setMaintenanceModeStatus(MaintenanceModeStatusEnum.ON);
		applicationControl.setMaintenanceModeDuration(duration);

		// Create a computer object and add the ApplicationControlComputerExtension
		Computer computer = new Computer();
		computer.setApplicationControl(applicationControl);

		// Update the computer
		ComputersApi computersApi = new ComputersApi();
		return computersApi.modifyComputer(computerId, computer, Boolean.FALSE, apiVersion);
	}
}
