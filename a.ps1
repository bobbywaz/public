# Prompt the user for a new computer name
$NewComputerName = Read-Host -Prompt "Enter the new computer name"

# Rename the computer
Rename-Computer -NewName $NewComputerName -Force

# Use PowerShell on Win+X
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$name = "DontUsePowerShellOnWinX"
$value = "0"
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} else {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n=allowGlobalConfirmation

# Install SpaceMonger
Invoke-WebRequest -Uri https://github.com/bobbywaz/public/raw/main/spacemonger.exe -OutFile C:\spacemonger.exe

# Expand system tray always
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWORD -Value 0 -Force | Out-Null

# Show all folders in navigation pane
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -PropertyType DWORD -Value 1 -Force | Out-Null

# Show file extensions
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWORD -Value 0 -Force | Out-Null

# Block crapware with Defender
Set-MpPreference -PUAProtection 1

# Enable dark mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -PropertyType DWORD -Force | Out-Null

# Set time zone
Set-TimeZone -Name "Eastern Standard Time"

# Install required apps
choco install googlechrome teamviewer 7zip notepadplusplus

# Uninstall OneDrive
Start-Process -FilePath "C:\windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait

# Make files without associations open with Notepad++
cmd /c 'assoc .="No Extension"'
cmd /c 'ftype "No Extension"="%ProgramFiles(x86)%\Notepad++\notepad++.exe" "%1"'
cmd /c 'assoc "No Extension"\DefaultIcon=%SystemRoot%\System32\imageres.dll,-102'

# Remove Intel tray icon
if (!(Test-Path -LiteralPath "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon")) {
    New-Item "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon" -Force -ErrorAction SilentlyContinue
}
New-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon" -Name "ShowTrayIcon" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null

# Remove Windows junk
$apps = @(
    "3dbuilder",
    "windowscommunicationsapps",
    "Appconnector",
    "candycrushsaga",
    "skypeapp",
    "zunemusic",
    "messaging",
    "onenote",
    "zunevideo",
    "people",
    "bingsports",
    "office.sway",
    "twitter"
)
foreach ($app in $apps) {
    Get-AppxPackage $app -AllUsers | Remove-AppxPackage -AllUsers
}

# Disable telemetry services
$telemetryServices = @(
    "DiagTrack",  # Connected User Experiences and Telemetry
    "dmwappushsvc", # dmwappushservice
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
)

foreach ($service in $telemetryServices) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# Disable telemetry tasks
$tasks = @(
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\Application Experience\AitAgent",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\Media Center\ActivateWindowsSearch",
    "\Microsoft\Windows\Media Center\ConfigureInternetTimeService",
    "\Microsoft\Windows\Media Center\DispatchRecoveryTasks",
    "\Microsoft\Windows\Media Center\ehDRMInit",
    "\Microsoft\Windows\Media Center\InstallPlayReady",
    "\Microsoft\Windows\Media Center\mcupdate",
    "\Microsoft\Windows\Media Center\MediaCenterRecoveryTask",
    "\Microsoft\Windows\Media Center\ObjectStoreRecoveryTask",
    "\Microsoft\Windows\Media Center\OCURActivate",
    "\Microsoft\Windows\Media Center\OCURDiscovery",
    "\Microsoft\Windows\Media Center\PBDADiscovery",
    "\Microsoft\Windows\Media Center\PBDADiscoveryW1",
    "\Microsoft\Windows\Media Center\PBDADiscoveryW2",
    "\Microsoft\Windows\Media Center\PvrRecoveryTask",
    "\Microsoft\Windows\Media Center\PvrScheduleTask",
    "\Microsoft\Windows\Media Center\RegisterSearch",
    "\Microsoft\Windows\Media Center\ReindexSearchRoot",
    "\Microsoft\Windows\Media Center\SqlLiteRecoveryTask",
    "\Microsoft\Windows\Media Center\UpdateRecordPath"
)

foreach ($task in $tasks) {
    schtasks /Change /TN $task /Disable
}

# Disable feedback and diagnostics
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force
New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force

# Disable Cortana
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force

# Disable location tracking
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force

# Disable advertising ID
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force

# Disable suggestions in Start Menu
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Force

# Disable Feedback frequency
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force

# Disable typing and inking data collection
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Force

# Disable Wi-Fi Sense
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowed" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedHotspot" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wHere is the combined PowerShell script that includes tasks for configuring a new computer and disabling telemetry and tracking in Windows 10/11:

```powershell
# Rename-computer
Rename-Computer -NewName "NewComputerName" -Force -Restart

# Use PowerShell on Win+X
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$name = "DontUsePowerShellOnWinX"
$value = "0"
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} else {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n=allowGlobalConfirmation

# Install SpaceMonger
Invoke-WebRequest -Uri http://exonetworks.net/apps/spacemonger.exe -OutFile C:\spacemonger.exe

# Expand system tray always
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWORD -Value 0 -Force | Out-Null

# Show all folders in navigation pane
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -PropertyType DWORD -Value 1 -Force | Out-Null

# Show file extensions
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWORD -Value 0 -Force | Out-Null

# Block crapware with Defender
Set-MpPreference -PUAProtection 1

# Enable dark mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -PropertyType DWORD -Force | Out-Null

# Set time zone
Set-TimeZone -Name "Eastern Standard Time"

# Install required apps
choco install googlechrome teamviewer 7zip notepadplusplus

# Uninstall OneDrive
Start-Process -FilePath "C:\windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait

# Update Windows
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate

# Make files without associations open with Notepad++
cmd /c 'assoc .="No Extension"'
cmd /c 'ftype "No Extension"="%ProgramFiles(x86)%\Notepad++\notepad++.exe" "%1"'
cmd /c 'assoc "No Extension"\DefaultIcon=%SystemRoot%\System32\imageres.dll,-102'

# Remove Intel tray icon
if (!(Test-Path -LiteralPath "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon")) {
    New-Item "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon" -Force -ErrorAction SilentlyContinue
}
New-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Intel\Display\igfxcui\igfxtray\TrayIcon" -Name "ShowTrayIcon" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null

# Remove Windows junk
$apps = @(
    "3dbuilder",
    "windowscommunicationsapps",
    "Appconnector",
    "candycrushsaga",
    "skypeapp",
    "zunemusic",
    "messaging",
    "onenote",
    "zunevideo",
    "people",
    "bingsports",
    "office.sway",
    "twitter"
)
foreach ($app in $apps) {
    Get-AppxPackage $app -AllUsers | Remove-AppxPackage -AllUsers
}

# Disable telemetry services
$telemetryServices = @(
    "DiagTrack",  # Connected User Experiences and Telemetry
    "dmwappushsvc", # dmwappushservice
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
)

foreach ($service in $telemetryServices) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# Disable telemetry tasks
$tasks = @(
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\Application Experience\AitAgent",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\Media Center\ActivateWindowsSearch",
    "\Microsoft\Windows\Media Center\ConfigureInternetTimeService",
    "\Microsoft\Windows\Media Center\DispatchRecoveryTasks",
    "\Microsoft\Windows\Media Center\ehDRMInit",
    "\Microsoft\Windows\Media Center\InstallPlayReady",
    "\Microsoft\Windows\Media Center\mcupdate",
    "\Microsoft\Windows\Media Center\MediaCenterRecoveryTask",
    "\Microsoft\Windows\Media Center\ObjectStoreRecoveryTask",
    "\Microsoft\Windows\Media Center\OCURActivate",
    "\Microsoft\Windows\Media Center\OCURDiscovery",
    "\Microsoft\Windows\Media Center\PBDADiscovery",
    "\Microsoft\Windows\Media Center\PBDADiscoveryW1",
    "\Microsoft\Windows\Media Center\PBDADiscoveryW2",
    "\Microsoft\Windows\Media Center\PvrRecoveryTask",
    "\Microsoft\Windows\Media Center\PvrScheduleTask",
    "\Microsoft\Windows\Media Center\RegisterSearch",
    "\Microsoft\Windows\Media Center\ReindexSearchRoot",
    "\Microsoft\Windows\Media Center\SqlLiteRecoveryTask",
    "\Microsoft\Windows\Media Center\UpdateRecordPath"
)

foreach ($task in $tasks) {
    schtasks /Change /TN $task /Disable
}

# Disable feedback and diagnostics
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force
New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force

# Disable Cortana
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force

# Disable location tracking
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force

# Disable advertising ID
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force

# Disable suggestions in Start Menu
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Force

# Disable Feedback frequency
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Force

# Disable typing and inking data collection
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Force

# Disable Wi-Fi Sense
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowed" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedHotspot" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared

# Update Windows
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate

