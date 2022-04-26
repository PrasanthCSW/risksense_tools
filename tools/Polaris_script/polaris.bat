:: ==========================================================================================================================================
:: This script is used to pull the data from Synopsys Polaris and push it to the Risksense Platform
:: User inputs : Polaris Token , Project Name , Branch Name , File name to get the results , Assessment name to be provided in config.txt file in order.
:: Usage --> polaris.bat <option>
:: 'option' can be , "O"(opened) or "C"(closed) , "A"(all) , "N"(New) , "F"(Fixed) , left blank(All)
:: ==========================================================================================================================================

@echo off


:: configuration part to be defined by the user from config.txt file

set "t="
for /F "skip=2" %%i in (config.txt) do if not defined t set "t=%%i"
set "project="
for /F "skip=3" %%i in (config.txt) do if not defined project set "project=%%i"
set "branch="
for /F "skip=4" %%i in (config.txt) do if not defined branch set "branch=%%i"
set "compare="
for /F "skip=5" %%i in (config.txt) do if not defined compare set "compare=%%i"
set "file="
for /F "skip=6" %%i in (config.txt) do if not defined file set "file=%%i"


if "%~1" == "C" goto closed
if "%~1" == "O" goto opened
if "%~1" == "A" goto all
if "%~1" == "F" goto fixed
if "%~1" == "N" goto new


:: All issues ( Closed/Opened )

:all

echo ================================================================================================================================================================
echo ===================================================================== Getting all issues for the branch %branch% =======================================================================
python getIssues.py  --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch%  --all --csv > %file%.csv

set "runid="
for /F "skip=1 delims=" %%i in (%file%.csv) do if not defined runid set "runid=%%i"


python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch% --run %runid% --all --csv --spec "name,description,b_name,url,issue-key,finding-key,severity,state,cwe,path,status,checker,type,Evidence,Vulnerability desc,Support description"  > upload_to_platform-master_branch\files_to_process\%file%.csv

python upload_to_platform-master_branch\upload_to_platform.py  

timeout /t 10
exit /b %ERRORLEVEL%" 


:: Closed issues

:closed

echo ================================================================================================================================================================
echo ===================================================================== Getting closed issues for the branch %branch%=======================================================================
python getIssues.py  --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch%  --closed --csv > %file%.csv

set "runid="
for /F "skip=1 delims=" %%i in (%file%.csv) do if not defined runid set "runid=%%i"



python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch% --run %runid% --closed --csv --spec "name,description,b_name,url,issue-key,finding-key,severity,state,cwe,path,status,checker,type,Evidence,Vulnerability desc,Support description"  > upload_to_platform-master_branch\files_to_process\%file%.csv

set "issue="
for /F "usebackq delims=,"  %%i in ("upload_to_platform-master_branch\files_to_process\%file%.csv") do if not defined issue set "issue=%%i"

:: echo %issue%

IF "%issue%" == "noissues" ( 
	Echo:
	Echo ----------------------------------------------- The defined spec doesn't have any issues -----------------------------------------------
	exit /b %ERRORLEVEL%" 
	)

python upload_to_platform-master_branch\upload_to_platform.py 

timeout /t 10
exit /b %ERRORLEVEL%" 


:: Opened issues

:opened

echo ================================================================================================================================================================
echo ===================================================================== Getting opened issues for the branch %branch% =======================================================================
python getIssues.py  --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch%  --opened --csv > %file%.csv

set "runid="
for /F "skip=1 delims=" %%i in (%file%.csv) do if not defined runid set "runid=%%i"

::echo %runid%

python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch% --run %runid% --opened --csv --spec "name,description,b_name,url,issue-key,finding-key,severity,state,cwe,path,status,checker,type,Evidence,Vulnerability desc,Support description"  > upload_to_platform-master_branch\files_to_process\%file%.csv

set "issue="
for /F "usebackq delims=,"  %%i in ("upload_to_platform-master_branch\files_to_process\%file%.csv") do if not defined issue set "issue=%%i"

::echo %issue%

IF "%issue%" == "noissues" ( 
	Echo:
	Echo ----------------------------------------------- The defined spec doesn't have any issues -----------------------------------------------
	exit /b %ERRORLEVEL%" 
	)

python upload_to_platform-master_branch\upload_to_platform.py 

timeout /t 10
exit /b %ERRORLEVEL%" 



:: New

:new

echo ================================================================================================================================================================
echo ===================================================================== Getting new issues by comparing %branch% branch with %compare% branch =======================================================================
python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch% --new --compare %compare% --csv > upload_to_platform-master_branch\files_to_process\%file%.csv 

set "issue="
for /F "usebackq delims=,"  %%i in ("upload_to_platform-master_branch\files_to_process\%file%.csv") do if not defined issue set "issue=%%i"

::echo %issue%

IF "%issue%" == "noissues" ( 
	Echo:
	Echo ----------------------------------------------- The defined spec doesn't have any issues -----------------------------------------------
	exit /b %ERRORLEVEL%" 
	)
python upload_to_platform-master_branch\upload_to_platform.py 
timeout /t 10
exit /b %errorlevel%



:fixed

echo ================================================================================================================================================================
echo ===================================================================== Getting fixed issues by comparing %branch% branch with %compare% branch =======================================================================
python getIssues.py --url https://ivanti.polaris.synopsys.com/ --token %t% --project %project% --branch %branch% --fixed --compare %compare% --csv > upload_to_platform-master_branch\files_to_process\%file%.csv 

set "issue="
for /F "usebackq delims=,"  %%i in ("upload_to_platform-master_branch\files_to_process\%file%.csv") do if not defined issue set "issue=%%i"

echo %issue%

IF "%issue%" == "noissues" ( 
	Echo:
	Echo ----------------------------------------------- The defined spec doesn't have any issues -----------------------------------------------
	exit /b %ERRORLEVEL%" 
	)
python upload_to_platform-master_branch\upload_to_platform.py 
timeout /t 10
exit /b %errorlevel%
