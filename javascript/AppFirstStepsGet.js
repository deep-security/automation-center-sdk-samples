var path = require("path");

const FirstStepsGetExample = require(path.resolve(__dirname, "lib/FirstStepsGetExample.js"));

FirstStepsGetExample.getPolicies("app.deepsecurity.trendmicro.com", "AC853399-6E03-0EDD-BF21-AE00AD9DD8E1:201:UhvOEpBk2HkwL+BCeNw3xkbtrw4HovvNa1JRKSSz2EQ=")
  .then(policies => {
    console.log(policies);
  })
  .catch(error => {
    console.log(error);
  });
