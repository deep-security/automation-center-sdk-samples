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

exports.getPolicies = function(hostUrl, apiSecretKey) {
  return new Promise((resolve, reject) => {
    // Deep Security module
    const api = require("@trendmicro/deepsecurity");

    // Create the client
    const defaultClient = api.ApiClient.instance;
    defaultClient.basePath = hostUrl;
    const defaultAuthentication = defaultClient.authentications["DefaultAuthentication"];
    defaultAuthentication.apiKey = apiSecretKey;

    // Allow connection that is 'secured' with self-signed certificate - for development only
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    // Create a PoliciesApi object
    const policiesApi = new api.PoliciesApi();

    // List policies. Use version v1 of the API
    policiesApi
      .listPolicies("v1")
      .then(policies => {
        resolve(policies);
      })
      .catch(error => {
        reject(error);
      });
  });
};
