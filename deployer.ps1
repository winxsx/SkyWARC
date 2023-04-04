$psexecPath = "C:\Users\Administrator\Downloads\PsExec.exe"
$targetIPs = Get-Content "C:\Users\Administrator\Documents\targets.txt"
$u1 = Read-Host "Enter the 1st batch of usernames"
$p1 = Read-Host "Enter the password for $u1"
$u2 = Read-Host "Enter the 2nd batch of usernames"
$p2 = Read-Host "Enter the passworf for $u2"

$credentials = @{
    "c1" = @{
        "Username" = $u1 ;
        "Password" = $p1
    }
    "c2" = @{
        "Username" = $u2;
        "Password" = $p2
    }
}


foreach ($ip in $targetIPs) {
    $selectedCredential = Read-Host "Enter the credential name (c1 or c2) for IP $ip"

    if ($credentials.ContainsKey($selectedCredential)) {
        $username = $credentials[$selectedCredential]["Username"]
        $password = $credentials[$selectedCredential]["Password"]

        & $psexecPath \\$ip -u $username -p $password -e -s powershell Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        & $psexecPath \\$ip -u $username -p $password -e -s powershell Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force
        & $psexecPath \\$ip -u $username -p $password -e -s powershell Set-SmbServerConfiguration -EnableSMB2Protocol 1 -Force
        & $psexecPath \\$ip -u $username -p $password -e -s powershell Set-ItemProperty -Path `"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`" SMB2 -Type DWORD -Value 1 -Force
        Write-Host "Invalid credential name. Skipping IP $ip."
    }
}