##TODO : test the windows 10 installation and start windows 7 installation

echo "Wazuh Manager and Sysmon Installation Service";
echo "";

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
[Security.Principal.WindowsBuiltInRole] "Administrator")) {

	Write-Error "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again.";
	Break;
	cmd /c pause;
}

else {
	Write-Host -ForegroundColor Green "Code is running as administrator go on executing the script..." ;
	$WazuhMgr = Read-Host -Prompt "Please Input Your Wazuh Manager Address";
	$WazuhGroup = Read-Host -Prompt "Please Input Your Wazuh Agent Group (Case Sensitive)";
	echo "Using $WazuhMgr as Wazuh Server and $WazuhGroup as Agent's group";
	echo "";

	echo "Detecting OS Version...";
	$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption;
	echo "OS Version Detected : $OSVersion";
	echo "";

	$isWindows10 = $OSVersion.Contains("Windows 10");
	$isWindows7 = $OSVersion.Contains("Windows 7");
	echo "";

	if($isWindows10){
		write-host -foreground green "Downloading wazuh installer";
		
		Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.0-1.msi -OutFile ${env:tmp}\wazuh-agent-4.3.0.msi;

		write-host -foreground green "Installing wazuh";
		msiexec.exe /i ${env:tmp}\wazuh-agent-4.3.0.msi /q WAZUH_MANAGER=$WazuhMgr WAZUH_REGISTRATION_SERVER=$WazuhMgr  WAZUH_AGENT_GROUP=$WazuhGroup;

		write-host - foreground green "Wazuh Agent installation successful, starting wazuh-agent";

		Net Start WazuhSvc

		write-host - foreground green "Wazuh Agent successfully started";
	}

	elseif($isWindows7){
		echo "Hey it's windows 7!";
	}

	else{
		Write-Error "This Version of Windows is not Supported";
	}

	cmd /c pause;
}