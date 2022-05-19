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
			Write-Warning "Cancelling installation..."
			Break;
		}
	}

	echo "Detecting OS Version...";
	$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption;
	echo "OS Version Detected : $OSVersion";
	echo "";

	$isWindows10 = $OSVersion.Contains("Windows 10");
	$isWindows7 = $OSVersion.Contains("Windows 7");
	echo "";

	if($isWindows10){
		
	}

	elseif($isWindows7){
		echo "Hey it's windows 7!";
	}

	else{
		Write-Error "This Version of Windows is not Supported";
	}

	cmd /c pause;
}