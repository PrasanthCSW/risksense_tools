# risksense_tools

A repository of tools that interact with the RiskSense API.

## Available Tools

* **appfinding_report_from_saved_filter**
  * A tool for generating a csv report based upon a saved filter in the platform.
* **tag_import_tool**
  * A tool for the mass creation of new tags via the reading of a .csv file.
* **cmdb_update_tool**
  * A tool for the mass update of hosts' CMDB information via the reading of a .csv file.
* **group_import_tool**
  * A tool for the mass creation of new groups via the reading of a .csv file.
* **hostfinding_report_from_saved_filter**
  * A tool for generating a csv report based upon a saved filter in the platform.

## Requirements
* A working [Python 3](https://python.org) installation is required.
* Additionally, the following Python packages are required:
  * [TOML](https://pypi.org/project/toml/)
  * [Requests](https://pypi.org/project/requests/)
  * [Progressbar2](https://pypi.org/project/progressbar2/)
  
The required packages can be installed with the following command:

    pip install -r requirements.txt

***Or***, depending on your installation of Python/Pip:

    pip3 install -r requirements.txt


## Installation
Download zip file, copy the file to the desired location, and unzip.
