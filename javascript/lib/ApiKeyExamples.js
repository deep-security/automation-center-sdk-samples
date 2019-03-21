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
 * Creates an API key with read-only permissions that expires in 2 weeks.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} keyName The name for the API key.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the created API key.
 */
exports.createAuditKey = function(api, keyName, apiVersion) {
  return new Promise((resolve, reject) => {
    // Key properties
    const key = new api.ApiKey();
    key.keyName = keyName;
    key.description = "Read-only access";
    key.roleID = "2";
    key.locale = api.ApiKey.LocaleEnum["en-US"];
    key.timeZone = "Asia/Tokyo";
    key.expiryDate = Date.now() + 1000 * 60 * 60 * 24 * 14;

    // Create the key on Deep Security Manager
    const apiKeysApi = new api.APIKeysApi();
    apiKeysApi
      .createApiKey(key, apiVersion)
      .then(newKey => {
        // Return the key ID
        resolve(newKey.ID);
      })
      .catch(error => {
        reject(error);
      });
  });
};

/*
 * Resets the secret key of an API key.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Integer} keyID The ID of the API key.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the secret of the key.
 */
exports.resetKeySecret = function(api, keyID, apiVersion) {
  return new Promise((resolve, reject) => {
    const apiKeysApi = new api.APIKeysApi();
    apiKeysApi
      .replaceApiSecretKey(keyID, apiVersion)
      .then(key => {
        resolve(key.secretKey);
      })
      .catch(error => {
        reject(error);
      });
  });
};
/*
 * Changes the role that an API key uses.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Integer} keyID The ID of the API key.
 * @param {Integer} roleID The ID of the role to use.
 * @param {String} apiVersion The API version to use.
 * @returns {Promise} A promise object that resolves to the ID of the role that the key uses.
 */
exports.modifyKeyRole = function(api, keyID, roleID, apiVersion) {
  return new Promise((resolve, reject) => {
    // Create a key and set the role ID
    const key = new api.ApiKey();
    key.roleID = roleID;

    //Modify the key on Deep Security Manager
    const apiKeysApi = new api.APIKeysApi();
    apiKeysApi
      .modifyApiKey(keyID, key, apiVersion)
      .then(key => {
        resolve(key.roleID);
      })
      .catch(error => {
        reject(error);
      });
  });
};
