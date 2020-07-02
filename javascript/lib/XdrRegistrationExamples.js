/*
 * Copyright 2020 Trend Micro.
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
 * Register XDR Service with the enrollment token.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} apiVersion The API version to use.
 * @param {String} registrationToken The XDR enrollment token.
 * @returns {Promise} A promise object that resolves to the ID of the XDR registration object.
*/
exports.createXdrRegistration = function (api, apiVersion, registrationToken) {
    return new Promise((resolve, reject) => {

        //Create the XDR registration object
        const xdrRegistration = new api.XdrRegistration();
        xdrRegistration.registrationToken = registrationToken;

        //Add the registry scanner to Deep Security Manager
        const xdrRegistrationApi = new api.XDRRegistrationApi();
        xdrRegistrationApi.createXdrRegistration(xdrRegistration, apiVersion)
        .then(returnedXdrRegistration => {
            resolve(returnedXdrRegistration.ID);
        })
        .catch(error => {
            reject(error);
        });
    });
};
