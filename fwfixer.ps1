$keyread = Get-Content -Path "C:\Users\fwUnlockKey.txt"
cmd /c sc sdset MpsSvc $keyread
$conf = Read-Host -Prompt "Continue with dropping? y/n"
$conf2 = Read-Host -Prompt "Are you sure? y/n"
if ($conf2 -eq 'y') {
    Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Recurse -Force
    net stop MpsSvc 
    net start MpsSvc
    Write-Host "Removed it"
}
elseif ($conf2 -eq 'n') {
    Write-Host "Aborting"
}
else {
    Write-Host "Invalid input"
}