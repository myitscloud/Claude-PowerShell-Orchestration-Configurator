# Claude-PowerShell-Orchestration-Configurator
SCCM or Manual PowerShell Orchestration for PC

Notes:
This is a “TEST” project of mine.
The project is using only AI (Claude in this case) to create basically a fully functional PowerShell Orchestration Platform for PC Deployments. I know very little PowerShell myself but am adequate with research and tweaking / editing code.
Most of the work has been refining prompts and defining projects to Claude AI, and grunt work like running the scripts hundreds of times and reinstalling OS on Hyper-V.
Quick Overview of how it works:
Inside Deploy folder is Scripts folder; 
a)	The Orchestration-Master is the file you will use to launch script
b)	The Orchestration-Config is the file that holds and contains nearly every option, setting, parameters, etc… Although sometimes you may need to view specific .PS1 task file to see if what you need is inside that file. For example you can enable/disable specific tasks with a $true/$false option.
c)	PsExec64.exe is used so that when needed all scripts will run as System. This may not be needed, but my end goal is to complete script, and then copy and rename default profile, save my current logged in profile as Default profile. (Note-not sure I am going about it correctly, but that is as best I understand it for now)
d)	The settings (Task .ps1) in Orchestration-Config are configured to NOT REBOOT, but after Windows updates, Drivers/Firmware Updates, or other tasks it is probably best to reboot.
e)	IMPORTANT! – Currently, if you do reboot, you will have to relaunch PWSH 7, and re-run commands to kick off script again, but use THIS command:
.\Orchestration-Master.ps1 -resume

And the script will do a check and continue where the last phase was at until it either fails, completes or needs to reboot again. Use the .\Orchestration-Master.ps1 -resume as many times as required to get the script to complete.
Troubleshooting- See below and clear all log file locations of files as the script looks to these files for resume functionality. Restart script 1st launch with command
.\Orchestration-Master.ps1 but if you do a reboot use .\Orchestration-Master.ps1 -resume

 
START HERE
Prerequisites-Non SCCM Non-Domain-Joined Manual Windows Operating System Installation
AKA via an: SCCM, MDT, Flash Drive, etc. or a Virtual Machine for testing
1)	Base Windows 11 Pro / Enterprise installation
2)	Setup first login account (Work or School Domain option)
3)	Install PowerShell 7.5.4
4)	Copy Deploy folder to C:\
5)	cd c:\Deploy\Scripts
 
6)	.\PsExec64.exe -accepteula -i -s pwsh.exe
 
7)	cd c:\Deploy\Scripts
 
8)	.\Orchestration-Master.ps1
9)	The script will execute. It will check for permissions, see which .PS! files are enabled, list a summary of what will and will not be performed and prompt user to continue by pressing any key
 
IF everything goes as planned and the script completes you will see a final overview summary and report.
To get more information navigate to:
C:\ProgramData\OrchestrationLogs
C:\ProgramData\ComplianceReports
C:\ProgramData\HealthReports

