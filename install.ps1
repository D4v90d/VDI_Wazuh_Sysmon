$WazuhMgr = Read-Host -Prompt "Please Input Wazuh Manager Address"
echo "Checking Wazuh Manager's Host Availability Via Ping"
ping $WazuhMgr
echo "Detecting OS Version";
$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption;
echo "OS Version Detected : $OSVersion"
cmd /c pause