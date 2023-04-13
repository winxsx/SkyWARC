#FW Service Hardener
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "Please run this script as an Administrator." 
    exit
}
#FW rules backup
$OutputFilePath = "FirewallRulesBackup.txt"
Get-NetFirewallRule | Export-Clixml -Path $OutputFilePath
Get-NetFirewallRule | Remove-NetFirewallRule
Write-Host "Current firewall rules have been saved to $OutputFilePath"
cmd /c "netsh advfirewall firewall add rule name=LDAP dir=in action=allow protocol=TCP localport=389"
cmd /c "netsh advfirewall firewall add rule name=SMTP dir=in action=allow protocol=TCP localport=25"
cmd /c "netsh advfirewall firewall add rule name=POP3 dir=in action=allow protocol=TCP localport=110"
cmd /c "netsh advfirewall firewall add rule name=HTTP dir=in action=allow protocol=TCP localport=80"
cmd /c "netsh advfirewall firewall add rule name=HTTPS dir=in action=allow protocol=TCP localport=443"
cmd /c "netsh advfirewall firewall add rule name=LDAP dir=in action=allow protocol=TCP localport=389"
cmd /c "netsh advfirewall firewall add rule name=localhost dir=in action=allow remoteip=127.0.0.0/8"
cmd /c "netsh advfirewall firewall add rule name=LAN dir=in action=allow remoteip=10.30.30.0/22"
cmd /c "netsh advfirewall firewall add rule name=IMAP dir=in action=allow protocol=TCP localport=143"
cmd /c "netsh advfirewall firewall add rule name=FTP dir=in action=allow protocol=TCP localport=21"
cmd /c "netsh advfirewall firewall add rule name=FTP-Passive dir=in action=allow protocol=TCP localport=20"
cmd /c "netsh advfirewall firewall add rule name=DNS dir=in action=allow protocol=UDP localport=53"
cmd /c "netsh advfirewall firewall add rule name=Kerberos dir=in action=allow protocol=TCP localport=88"

cmd /c "netsh advfirewall firewall add rule name=LAN dir=out action=allow remoteip=10.30.30.0/22"
cmd /c "netsh advfirewall firewall add rule name=localhost dir=out action=allow remoteip=127.0.0.0/8"
cmd /c "netsh advfirewall firewall add rule name=DNS dir=out action=allow protocol=UDP remoteport=53 remoteip=9.9.9.9"




# Display a message indicating the successful completion of the script
Write-Host "Current firewall rules have been saved to $OutputFilePath and deleted."
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