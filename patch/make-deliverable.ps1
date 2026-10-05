# Bake DetectorShim.exe (base64) into the shipped patcher and write it with a UTF-8 BOM
# so Windows PowerShell 5.1 renders the Chinese text correctly.
#
# Build order:
#     DetectorShim.cs -> build-shim.ps1 -> DetectorShim.exe -> this -> uu-remote-patcher.ps1
#
# Edit the *template*, never the generated uu-remote-patcher.ps1 - this script overwrites it.
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$tpl  = Join-Path $here "uu-remote-patcher.template.ps1"
$exe  = Join-Path $here "DetectorShim.exe"
$out  = Join-Path $here "uu-remote-patcher.ps1"

if (-not (Test-Path $exe)) { throw "missing $exe - run build-shim.ps1 first" }

$txt = [System.IO.File]::ReadAllText($tpl, [System.Text.Encoding]::UTF8)
if ($txt.IndexOf("__SHIM_B64__") -lt 0) { throw "placeholder not found in template" }

# Emit the base64 blob with the *template's* newline style, so the output never ends up
# with mixed line endings whichever way git checks the file out.
$nl = if ($txt.Contains("`r`n")) { "`r`n" } else { "`n" }

$raw   = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($exe))
$chunks = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $raw.Length; $i += 120) {
    $chunks.Add($raw.Substring($i, [Math]::Min(120, $raw.Length - $i)))
}
$b64 = [string]::Join($nl, $chunks)

$final = $txt.Replace("__SHIM_B64__", $b64)

[System.IO.File]::WriteAllText($out, $final, (New-Object System.Text.UTF8Encoding($true)))
$f = Get-Item $out
Write-Output ("wrote {0}  size={1}  exeB64={2} chars  newline={3}" -f `
    $f.FullName, $f.Length, $raw.Length, $(if ($nl -eq "`r`n") { "CRLF" } else { "LF" }))
