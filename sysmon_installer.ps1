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
	$SysmonChk = Sysmon;

	$isSysmonInstalled = $OSVersion.Contains("System Monitor");

	if($isSysmonInstalled){
		$isUninstall = Read-Host -ForeGroundColor Yellow -Prompt "We Detected System Monitor to be already installed proceed to uninstall Sysmon and install a newer version? [y/n]";

		$isContinue = $isUninstall -eq "y"
		if ($isContinue){
			Write-Warning "Uninstalling current Sysmon"
			sysmon -u
		}
		else{
			Break;
		}
	}

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