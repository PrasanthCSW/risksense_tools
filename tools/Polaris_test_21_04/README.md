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