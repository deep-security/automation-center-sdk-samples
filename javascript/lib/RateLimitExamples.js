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

/**
 * Assigns a policy to a number of computers. Checks for exceeded API rate limits and tries again.
 *
 * @param {Number[]} computerIDs An array of computer IDs to assign the policy.
 * @param {Number} policyID The ID of the policy to assign.
 * @param {Object} api The Deep Security API module.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} Contains an array of IDs of the computers that were modified.
 */
exports.setComputerPolicyAndCheckRateLimits = function(computerIDs, policyID, api, apiVersion) {
  const max_retries = 10; // Maximum number of retries to attempt before aborting
  const computersApi = new api.ComputersApi();

  // Create the computer object and set the policy ID
  const computer = new api.Computer();
  computer.policyID = policyID;

  // Modify the computers and store the promises in an array
  const promises = [];
  for (let i = 0; i < computerIDs.length; i++) {
    promises.push(modifyRecursive(computerIDs[i]));
  }

  //Return the promises when they are all resolved
  return Promise.all(promises);

  /*
   * Modfies a computer on Deep Security Manager. If an API rate limit is exceded, the function
   * is called again after a short delay.
   */
  function modifyRecursive(computerID, retry = 0) {
    return new Promise((resolve, reject) => {
      // Modify the computer on the manager
      computersApi
        .modifyComputer(computerID, computer, apiVersion, { overrides: false })
        .then(returnedComputer => {
          // Resolve the ID of the modified computer
          resolve(returnedComputer.ID);
        })
        .catch(function(error) {
          if (error === "Too many API requests." && retry <= max_retries) {
            // API rate limit is exceeded - calculate retry delay
            const expBackoff = Math.pow(2, retry + 3);
            console.log(`API rate limit exceeded. Trying again in ${expBackoff} ms.`);
            setTimeout(() => {
              resolve(modifyRecursive(computerID, retry + 1));
            }, expBackoff);
          } else {
            // Any other errors or maximum retries is exceeded
            reject(error);
          }
        });
    });
  }
};
