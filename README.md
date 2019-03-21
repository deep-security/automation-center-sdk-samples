# automation-center-sdk-samples

This repository contains sample code for the Trend Micro Deep Security SDK. The examples in the [Automation Center](https://automation.deepsecurity.trendmicro.com) guides are based on these samples. Samples for each programming language are located in the python, javascript, and java folders. 

## Contents

* [Branches](#branches)
* [Run the Samples](#run-the-samples)
  * [Download or clone this repository](#download-or-clone-this-repository)
  * [Get the SDK](#get-the-sdk)
  * [Run the Python samples](#run-the-python-samples)
  * [Run the JavaScript samples](#run-the-javascript-samples)
  * [Run the Java samples](#run-the-java-samples)

## Branches

The samples in the master branch of this repository are compatible with the current version of Deep Security as a Service. They are not guaranteed to run correctly with previous versions installed on other platforms. 

**Note:** The tenant-related examples are not supported on Deep Security as a Service, as this platform does not offer the tenant feature.

As new releases of Deep Security are released, branches are created and named according to the version of Deep Security with which they are compatible.

## Run the samples

Perform the steps in the following sections to run the samples.

### Download or clone this repository

Download or clone this repository to create a local copy.

#### Download

If you are not familiar with GitHub or Git, you can download a ZIP file that contains the repository.

1. Click **Clone or Download > Download ZIP**.
1. Unzip the archive on your file system.

#### Clone

1. Click **Clone or Download**.
1. Copy the repository web url for cloning with HTTPS (`https://github.com/deep-security/automation-center-sdk-samples.git`).
1. Open a command line interface and change the current directory to the desired location of the local repository.
1. Enter `Git clone https://github.com/deep-security/automation-center-sdk-samples.git`.

### Get the SDK

Install the SDK and required software for the language that you are interested in. SDK download and installation instructions are on the Automation Center:

* [Python](https://automation.deepsecurity.trendmicro.com/article/python)
* [JavaScript](https://automation.deepsecurity.trendmicro.com/article/javascript3)
* [Java](https://automation.deepsecurity.trendmicro.com/article/java) -- Note that if you are importing the provided Eclipse project, you add the SDK to your project's build path after you import the project. See the [Run the Java samples](#run-the-java-samples) section.

### Run the Python samples

1. Open a command line interface and change the current directory to the `automation-center-sdk-samples` directory of your local repository.
1. Enter the following command to create a new Git branch: `git checkout -b run_examples`
1. In the ./python/src folder, create a file named properties.json and save the following JSON code into it, replacing the values for `url`  and `secretkey` with the URL and API key for your Deep Security Manager instance:
		
		{
    		"url": "https://192.168.17.143:4119/api",
    		"secretkey": "2:HNVgA9U0Gf1F/+GtKB58ITFJkoCVxysoz/vTi5NmLPk="
		}

	**Note:** The properties.json file is listed in the .gitignore file so it is not included in the repository. In this way, this sensitive data is not shared outside your local hard drive.

1. Open the ./python/src/main.py file.
  1. Replace any environment-specific values that are used as arguments for running sample modules, such as `policy_id`.
  1. Comment-out any `print` statements that you do not want to execute. 
  1. Save the file
1. In the command line interface, change the current directory to `./python/src` and then enter `python main.py`.

### Run the JavaScript samples

1. Open a command line interface and change the current directory to the `automation-center-sdk-samples` directory of your local repository.
1. Enter the following command to create a new Git branch: 
		git checkout -b run_examples
1. In the ./javascript folder, create a file named properties.json and save the following JSON code into it, replacing the values for `url`  and `secretkey` with the URL and API key for your Deep Security Manager instance:

		{
    		"url": "https://192.168.17.143:4119/api",
    		"secretkey": "2:HNVgA9U0Gf1F/+GtKB58ITFJkoCVxysox/vTi5NmLPk="
		}
		
	**Note:** The properties.json file is listed in the .gitignore file so it is not included in the repository. In this way, this sensitive data is not shared outside your local hard drive.

1. Open the ./javascript/App.js file.
  1. Replace any environment-specific values that are used as arguments for running sample modules, such as `policyID`.
  1. Comment-out the commands that you do not want to execute, and uncomment the commands that you want to execute. 
  1. Save the file
1. In the command line interface, change the current directory to `./javascript/` and then enter `node App.js`.

### Run the Java samples

1. Open a command line or terminal and change the current directory to the `automation-center-sdk-samples` directory of your local repository.
1. Enter the following command to create a new Git branch: 
	`git checkout -b run_examples`
1. Open Eclipse and click **File > Import**.
1. Select **General > Projects from Folder or Archive** and cick **Next**.
1. Click **Directory** and select the `java` folder in your local repository.
1. Click **Finish**.
1. In the Project Explorer, right-click the project folder and click **Properties**.
1. Click **Java Build Path**, click the **Libraries** tab, and then click **External JARs**.
1. Go to the folder that contains the extracted Java SDK, select the deepsecurity-xx.x.xxx.jar file, and click **Open**.
1. Similarly, add all of the files in the lib sub folder from the SDK.
1. Click **Apply** and **Close**.
1. Below src, right-click **com/trendmicro/deepsecurity/docs/Resources** and click **New > File**. (Depending on your version of Eclipse, you might have to click **New > Other**, then select **General/File**.)
1. Create a file named `example.properties` and add the following text into it, replacing the values for `url`  and `secretkey` with the URL and API key for your Deep Security Manager instance:

		secretkey=2:HNVgA9U0Gf1F/+GtKB58ITFJkoCVxysox/vTi5NmLPk=
		url=https://192.168.17.143:4119
		
	**Note:** The example.properties file is listed in the .gitignore file so it is not included in the repository. In this way, this sensitive data is not shared outside your local hard drive.
1. Open the `src/com.trendmicro/deepsecurity/docs/RunExamples.java` file. The file contains code that runs policy-related examples. To run other examples, add similar code.
1. Change the values of the global variables according to your Deep Security Manager instance, such as the `computerID` variable.
1. Click **Run > Run As > Java Application**.
