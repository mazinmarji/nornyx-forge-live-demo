# Create a local standard-user account on a CI runner and run the installer
# checks (standard_user_checks.py, "standard-user" mode) as that account.
#
# Meant for a throw-away GitHub-hosted Windows runner only. The account is
# created in the Users group alone, with a random password that exists in this
# script's memory and nowhere else, and it is given read access to a COPY of the
# checkout's scripts and sources and to the artifact, and write access to its
# own work folder. Nothing is installed for the runner's administrator.
#
# Output of the checks is printed after they finish; the exit code is theirs.
param(
  [Parameter(Mandatory = $true)][string]$Python,
  [Parameter(Mandatory = $true)][string]$Checkout,
  [Parameter(Mandatory = $true)][string]$ArtifactSource
)
$ErrorActionPreference = "Stop"
$name = "forgeci"
$share = "C:\forge-ci"
$password = "Fc1!" + [guid]::NewGuid().ToString("N")
$secure = ConvertTo-SecureString $password -AsPlainText -Force

# What the account may read: the checkout's scripts and the two sources the
# scripts import, laid out as the scripts expect (scripts\, src\nornyx_forge\).
New-Item -ItemType Directory -Force "$share\repo\src\nornyx_forge", "$share\work" | Out-Null
Copy-Item -Recurse -Force "$Checkout\scripts" "$share\repo\scripts"
Copy-Item -Force "$Checkout\src\nornyx_forge\__init__.py", "$Checkout\src\nornyx_forge\windows_payload.py" "$share\repo\src\nornyx_forge"
Copy-Item -Recurse -Force $ArtifactSource "$share\artifact"

New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -Group "Users" -Member $name
$administrators = @(Get-LocalGroupMember -Group "Administrators" | ForEach-Object { $_.Name })
if ($administrators -match "\\$name$") { throw "$name is an administrator; the account must be a standard user" }

& icacls "$share\repo" /grant "${name}:(OI)(CI)RX" /T | Out-Null
& icacls "$share\artifact" /grant "${name}:(OI)(CI)RX" /T | Out-Null
& icacls "$share\work" /grant "${name}:(OI)(CI)M" | Out-Null

$credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$name", $secure)
$driver = "$share\repo\scripts\windows_installer\standard_user_checks.py"
$out = "$share\work\driver.out"
$err = "$share\work\driver.err"
$process = Start-Process -FilePath $Python `
  -ArgumentList @("-B", "`"$driver`"", "standard-user", "--artifact", "`"$share\artifact`"", "--work", "`"$share\work`"") `
  -Credential $credential -LoadUserProfile -WorkingDirectory "$share\work" `
  -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru
Write-Host "---- driver output"
if (Test-Path $out) { Get-Content $out | Write-Host }
Write-Host "---- driver errors"
if (Test-Path $err) { Get-Content $err | Write-Host }
Write-Host "---- driver exit code $($process.ExitCode)"
exit $process.ExitCode
