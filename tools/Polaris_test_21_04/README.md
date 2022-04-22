# polaris.bat

This script is used to pull the data from Synopsys Polaris and push it to the Risksense Platform.

# User inputs

Polaris Token , Project Name , Branch Name , File name to get the results , Assessment name to be provided in config.txt file in order.

# config.txt 

<polaris token>
<project name>
<branch name>
<comparison branch name> --> This is optional, to be left blank if comparison not needed.
file_name --> File name to which the data is exported to from the Synopsys polaris.
Assessment_ --> Assessment name to be created in Risksense.

# upload_to_platform-master_branch\conf\config.toml

Enter the Risksense Platform URL and API key in config.toml file under "upload_to_platform-master_branch\conf" ; 

* https://platform4.risksense.com 
* API Key - 'xxxx'   ---> to be generated in Risksense platform for a user.


Once these values are entered, you can run the script as;

# Usage 

polaris.bat <option>

'option' can be , 

* "O"(opened) or "C"(closed) , "A"(all) , "N"(New) , "F"(Fixed) , left blank(All)

======================================================================================================================================

Developed by;

Prasanth Bharadhwaaj ,
Yugesh ,
Jai Balaji ,
Security Analyst - CSW.
