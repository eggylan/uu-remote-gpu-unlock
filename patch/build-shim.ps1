# Build DetectorShim.exe with the in-box .NET Framework C# compiler (Windows PowerShell 5.1).
$ErrorActionPreference = "Stop"
$src = Join-Path $PSScriptRoot "DetectorShim.cs"
$out = Join-Path $PSScriptRoot "DetectorShim.exe"
if (Test-Path $out) { Remove-Item $out -Force }
Add-Type -Path $src -OutputAssembly $out -OutputType ConsoleApplication
$f = Get-Item $out
Write-Output ("built: {0}  size={1}" -f $f.FullName, $f.Length)
