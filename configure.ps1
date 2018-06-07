# Script must be run with . path\to\prep.ps1 (for example . .\prep.ps1 if it's in current working folder) for the code below to elevate the right process.


# Function to remove all registry values of the key
function Remove-AllItemProperties {
    [CmdletBinding()]
    param([string]$Path)

    Remove-ItemProperty -Name * @PSBoundParameters
}



function enable-privilege {
    param(
        ## The privilege to adjust. This set is taken from
        ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )

    ## Taken from P/Invoke.NET with minor adjustments.
    $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

enable-privilege SeTakeOwnershipPrivilege 
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::takeownership)
# You must get a blank acl for the key b/c you do not currently have access
$acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
$me = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
$acl.SetOwner($me)
$key.SetAccessControl($acl)

# After you have set owner you need to get the acl with the perms so you can modify it.
$acl = $key.GetAccessControl()
$rule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Administrators", "FullControl", "Allow")
$acl.SetAccessRule($rule)
$key.SetAccessControl($acl)

$key.Close()

###### End code copied from the internet


#Turn off System Restore
$logicaldrives = get-wmiobject win32_logicaldisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID
foreach ($drive in $logicaldrives) {
    Write-Host "Disabling system restore on" + $drive.deviceid
    Disable-ComputerRestore $drive.deviceid
}


# Set power configuration to 'High performance', don't run this on XP
$MyPlan = "High Performance"
Write-Host "Setting Power Plan to $MyPlan"
$guid = (Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName='$MyPlan'").InstanceID.tostring()
$regex = [regex]"{(.*?)}$"
$newPower = $regex.Match($guid).groups[1].value
POWERCFG -S $newPower
Write-Host "Setting Standby Timeout to Never"
POWERCFG -change -standby-timeout-ac 0
Write-Host "Setting Monitor Timeout to Never"
POWERCFG -change -monitor-timeout-ac 0
Write-Host "Disabling hibernation"
POWERCFG -h off


# Configure windows visual settings for "Best Performance"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" -Name "ThemeActive" -Value "" -PropertyType STRING -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value "2" -PropertyType DWORD -Force


# Disable screensaver, Win10 version
New-PSDrive -PSProvider registry -Root HKEY_USERS -Name HKU
New-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0" -PropertyType STRING -Force
New-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value "" -PropertyType STRING -Force


# Config automatic update
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value "2" -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value "1" -PropertyType DWORD -Force # Try to disable WU in another way

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "Ethernet" -Value "2" -PropertyType DWORD -Force


#Disable scheduled tasks
$scheduledtasks = (schtasks.exe /QUERY /V /FO "CSV" | ConvertFrom-Csv ) | Where-Object {($_.status -ne "Status") -and ($_.status -ne "") -and ($_."Next Run Time" -ne "N/A")}
if ($scheduledtasks) {
    foreach ($task in $scheduledtasks) {
        Write-Host "Disabling scheduled task" $task.TaskName
        schtasks.exe /change /TN $task.TaskName /DISABLE
    }
}
$scheduledtasks = (schtasks.exe /QUERY /V /FO "CSV" | ConvertFrom-Csv ) | Where-Object {($_."Logon Mode" -eq "Interactive/Background")}

if ($scheduledtasks) {
    foreach ($task in $scheduledtasks) {
        Write-Host "Disabling scheduled task" $task.TaskName
        schtasks.exe /change /TN $task.TaskName /DISABLE
    }
}


# Force use platform clock
Write-Host "Enabling platform clock"
bcdedit /set USEPLATFORMCLOCK true


# Enable remote logon settings (RDP)
Write-Host "Allowing remote desktop connections"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnection" -Value "4" -PropertyType DWORD -Force # RDP


# Disable Windows Defender
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "1" -PropertyType DWORD -Force 


# Install Python
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
Invoke-WebRequest -Uri https://www.python.org/ftp/python/2.7.15/python-2.7.15.msi -OutFile python.msi
msiexec /i "python.msi" /qn /passive /norestart ADDLOCAL=ALL TARGETDIR=C:\Python27
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Python27", [EnvironmentVariableTarget]::Machine)


# Add 'testuser' user to Administrators group
net localgroup Administrators testuser /add


# Autologon
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" -PropertyType STRING -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Value $Env:USERDOMAIN -PropertyType STRING -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "testuser" -PropertyType STRING -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "" -PropertyType STRING -Force


# Security Policies
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0" -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value "0" -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value "0" -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0" -PropertyType DWORD -Force


# Add to startup 
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Custom_script" -Value "E:\perf_autorun.bat" -PropertyType STRING -Force


# Re-configure execution policies
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Bypass" -PropertyType STRING -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Bypass" -PropertyType STRING -Force


# Associate .ps1 extension to run in powershell instead of editing
cmd.exe /c ftype Microsoft.PowerShellScript.1=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%1" %*


# Uninstall AppX
#Get-AppxPackage -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
# if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
#     New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force 
# }
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value "2" -PropertyType DWORD -Force # Stop auto download for all users
# if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
#     New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force 
# }
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1" -PropertyType DWORD -Force # Policy only works on Enterprise version


# Disabling services
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -Value "4" -PropertyType DWORD -Force # Windows Update
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Delivery Optimization
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # WU Medic Service
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Update Orchestration
# New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TrustedInstaller" -Name "Start" -Value "3" -PropertyType DWORD -Force # Windows Modules Installer, manual (3) by default, if want to change ownership must be taken from TrustedInstaller
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "Start" -Value "4" -PropertyType DWORD -Force # Windows Search
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UevAgentService" -Name "Start" -Value "4" -PropertyType DWORD -Force # User Experience Virtualization
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name "Start" -Value "4" -PropertyType DWORD -Force # Auto Timezone
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\shpamsvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Shared PC account manager
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SCardSvr" -Name "Start" -Value "4" -PropertyType DWORD -Force # Smart card
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value "4" -PropertyType DWORD -Force # Superfetch
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value "4" -PropertyType DWORD -Force # Remote registry
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value "4" -PropertyType DWORD -Force # Routing and remote
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PhoneSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Phone service
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" -Name "Start" -Value "4" -PropertyType DWORD -Force # NetTCP port sharing
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Geolocation 
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppVClient" -Name "Start" -Value "4" -PropertyType DWORD -Force # App-V client
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # WMP Network Sharing Service
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # Optimize drives a.k.a. Disk Defragment
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SDRSVC" -Name "Start" -Value "4" -PropertyType DWORD -Force # Windows Backup
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Themes" -Name "Start" -Value "4" -PropertyType DWORD -Force # Themes
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule" -Name "Start" -Value "4" -PropertyType DWORD -Force # Task Scheduler
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time" -Name "Start" -Value "4" -PropertyType DWORD -Force # Windows Time
# New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppReadiness" -Name "Start" -Value "4" -PropertyType DWORD -Force # App Readiness, without this there will be no Candy Crush, others Metro apps, even Settings app
# New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Value "4" -PropertyType DWORD -Force # AppX Deployment, without this there will be no Metro interface at all, including Start Menu and Notification Center


# Insurance, deny SYSTEM from accessing wuauserv registry key. May need to do the same to DoSvc, WaaSMedicSvc and UsoSvc
$acl = Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv
$acl.SetOwner($me)
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny")
$acl.AddAccessRule($rule)
$acl | Set-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv


# Set Helsinki timezone
Set-TimeZone -Name "FLE Standard Time"


# Disable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False


# Remove all device mappings so KVM will define drives' order
Remove-AllItemProperties("HKLM:\SYSTEM\MountedDevices")


# And then reboot (for those policies and service settings to take effect)
shutdown -r -t 10