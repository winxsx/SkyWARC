#FW Service Hardener
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "Please run this script as an Administrator." 
    exit
}

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft"
$key = "WindowsFirewall"
$keyD = "DomainProfile"
$keyPriv = "PrivateProfile"
$keyPub = "PublicProfile"
$keylist = $keyD, $keyPriv, $keyPub


if (-not(Test-Path "$RegPath\$key")) {
    New-Item -Path "$RegPath" -Name $key -Force | Out-Null
    $NewRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    New-Item -Path "$NewRegPath" -Name $keyD -Force | Out-Null
    New-Item -Path "$NewRegPath" -Name $keyPriv -Force | Out-Null
    New-Item -Path "$NewRegPath" -Name $keyPub -Force | Out-Null
}
ForEach ($item in $keylist) {
Set-ItemProperty -Path "$NewRegPath\$item" -Name "EnableFirewall" -Value 1 -Force
Set-ItemProperty -Path "$NewRegPath\$item" -Name "DefaultInboundAction" -Value 1 -Force
Set-ItemProperty -Path "$NewRegPath\$item" -Name "DefaultOutboundAction" -Value 1 -Force
}
cmd /c "netsh firewall set logging C:\fwlogs.txt 32767 ENABLE ENABLE"

#GP Local Lock
$GPORegPath = "HKCU:\Software\Policies\Microsoft\MMC"
if (!(Test-Path $GPORegPath)) {
    New-Item -Path $GPORegPath -Force
}
$GPORegPath += "\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}"
if (!(Test-Path $GPORegPath)) {
    New-Item -Path $GPORegPath -Force
}
New-ItemProperty -Path $GPORegPath -Name "Restrict_Run" -Value 1 -PropertyType DWORD -Force
Write-Host "GP Local Denied"

#FW Key saved
if (Test-Path -Path "C:\Users\fwUnlockKey.txt") {
    Write-Host "The file exists."
} else {
    cmd.exe /c "sc sdshow MpsSvc" > "C:\Users\fwUnlockKey.txt"
    Write-Host "Saved SD to C:\Users\fwUnlockKey.txt"
}

#Restart FW service and harden
net stop MpsSvc 
$exit1 = $LASTEXITCODE
net start MpsSvc
$exit2 = $LASTEXITCODE
if ($exit1 -eq 0 -and $exit2 -eq 0){
    Write-Host "Restart Successful"
    Start-Process -FilePath "sc.exe" -ArgumentList 'sdset', 'MpsSvc', 'D:(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPDTLOCRRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLORC;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)' -NoNewWindow -Wait
} else {
    Write-Host "Error in stop $exit1 or error in $exit2"
    }

Write-Host "Hardened FW"