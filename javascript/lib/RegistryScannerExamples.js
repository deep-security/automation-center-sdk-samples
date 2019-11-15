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
 * Adds a registry scanner to Deep Security Manager.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The API version to use.
 * @param {String} name The name or IP address of the registry scanner.
 * @param {String} url The url of the registry scanner.
 * @param {String} user_account The user account that can login to the registry scanner.
 * @param {String} user_password The password of the user.
 * @returns {Promise} A promise object that resolves to the ID of the registry scanner.
*/
exports.createRegistryScanner = function (api, apiVersion, name, url, user_account, user_password) {
    return new Promise((resolve, reject) => {

        //Create the registry scanner object
        const registryScanner = new api.RegistryScanner();
        registryScanner.name = name;
        registryScanner.url = url;
        registryScanner.username = user_account;
        registryScanner.password = user_password;

        //Add the registry scanner to Deep Security Manager
        const registryScannersApi = new api.RegistryScannersApi();
        registryScannersApi.createRegistryScanner(registryScanner, apiVersion)
        .then(returnedRegistryScanner => {
            resolve(returnedRegistryScanner.ID);
        })
        .catch(error => {
            reject(error);
        });
    });
};