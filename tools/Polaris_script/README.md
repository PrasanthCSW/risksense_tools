# polaris.bat

This script is used to pull the data from Synopsys Polaris and push it to the Risksense Platform.

# User inputs

Polaris Token , Project Name , Branch Name , File name to get the results , Assessment name to be provided in config.txt file in order.

# config.txt 

"polaris token" -- Replace "polaris token" with the polaris token.</br>
"project name" -- Replace "project name" with the project name.</br>
"branch name" -- Replace "branch name" with the branch name.</br>
"comparison branch name" -- This is optional, to be left blank if comparison not needed.(Replace <comparison branch name> with the comparison branch name).</br>
file_name -- File name to which the data is exported to, from the Synopsys polaris.(Replace file_name with any name for the file, no extension is required)</br>
Assessment_ -- Assessment name to be created in Risksense.(Replace this text with the Assessment name , not really necessary to change).</br>

 * Example:
  
thisisthetoken1223421 </br>
Centralcore.SM </br>
master </br>
SAST </br>
file_test </br>
Assessment_ </br>
  
  
# upload_to_platform-master_branch\conf\config.toml

Enter the Risksense Platform URL and API key in config.toml file under "upload_to_platform-master_branch\conf" ; 

* https://platform4.risksense.com 
* API Key - 'xxxx'   ---> to be generated in Risksense platform for a user.
* Client ID - 213132 ( hovering over your user initials will provide the ID of the current client you are logged into )


Once these values are entered, you can run the script as;

# Usage 

polaris.bat "option"
  
  * Example : polaris.bat C

'option' can be , 

* "O"(opened) or "C"(closed) , "A"(all) , "N"(New) , "F"(Fixed) , left blank(All)

======================================================================================================================================

Developed by;

Prasanth Bharadhwaaj ,</br>
Yugesh ,</br>
Jai Balaji ,</br>
Security Analyst - CSW.
