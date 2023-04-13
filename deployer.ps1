$psexecPath = "C:\Users\Administrator\Downloads\paexec.exe"
$targetIPs = Get-Content "C:\Users\Administrator\Downloads\targets.txt"
$u1 = Read-Host "Enter the 1st batch of usernames"
$p1 = Read-Host "Enter the password for $u1"
$u2 = Read-Host "Enter the 2nd batch of usernames"
$p2 = Read-Host "Enter the password for $u2"
$u3 = Read-Host "Enter the 3rd batch of usernames"
$p3 = Read-Host "Enter the password for $u3"

$credentials = @{
    "c1" = @{
        "Username" = $u1 ;
        "Password" = $p1
    }
    "c2" = @{
        "Username" = $u2;
        "Password" = $p2
    }
    "c3" = @{
        "Username" = $u3;
        "Password" = $p3
    }
}


foreach ($ip in $targetIPs) {
    $selectedCredential = Read-Host "Enter the credential name (c1,c2,c3) for IP $ip"

    if ($credentials.ContainsKey($selectedCredential)) {
        $username = $credentials[$selectedCredential]["Username"]
        $password = $credentials[$selectedCredential]["Password"]     
    }
    & $psexecPath \\$ip -u $username -p $password -c -d -f C:\Users\Administrator\Downloads\init.ps1 -lo C:\lol.log
    & $psexecPath \\$ip -u $username -p $password -c -d -f C:\Users\Administrator\Downloads\hardenFW.ps1 -lo C:\lol.log
    & $psexecPath \\$ip -u $username -p $password -h -s -d powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Administrator\Downloads\init.ps1" -lo C:\lol.log
    & $psexecPath \\$ip -u $username -p $password -h -s -d powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Administrator\Downloads\hardenFW.ps1" -lo C:\lol.log

}