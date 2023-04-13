
#change pass
net user Administrator 6969bingbong!

#disable SMBv1
$osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
if ($osVersion -ge "6.1" -and $osVersion -lt "6.3") {
        Write-Host "Disabling SMBv1 on Windows 7, Windows Server 2008 R2, or Windows Server 2012"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Force
        sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
        sc.exe config mrxsmb10 start= disabled
    } else {
        Write-Host "Disabling SMBv1 on Windows 10, Windows Server 2016, or Windows Server 2019"
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  
}

