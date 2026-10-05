[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Netease\GameViewer\bin",
    [int]$WaitMinutes = 15,
    [switch]$Restore,
    [switch]$NoPrompt,
    [switch]$SkipAdminCheck
)

$ErrorActionPreference = "Stop"

$StockDllSha   = "2DB8630CB0D73B54135FF972AD82FC053FDEFF5117E67C5DD295EC4020C73276"
$PatchOffset   = 0x9B172F
$PatchOld      = [byte[]](0xB8, 0x05, 0x00, 0x00, 0x00)   # mov eax, 5  (未知厂商 -> class 5 = 不可探测)
$PatchNew      = [byte[]](0xB8, 0x02, 0x00, 0x00, 0x00)   # mov eax, 2  (未知厂商 -> class 2 = DXVA11 可探测)
$PatchLen      = 5

$Dll        = Join-Path $InstallDir "streamer.dll"
$DllStock   = Join-Path $InstallDir "streamer.dll.stock"
$Detector   = Join-Path $InstallDir "StreamerCodecDetector.exe"
$DetStock   = Join-Path $InstallDir "StreamerCodecDetector.orig.exe"
$ConfigDir  = Join-Path (Split-Path -Parent $InstallDir) "config\streamer"
$Cache      = Join-Path $ConfigDir "decoder_codec_capability_cache.json"
$InstallRoot = Split-Path -Parent $InstallDir
$ShimLog    = Join-Path $env:TEMP "uu_detector_shim.log"

function Say  { param($m) Write-Host $m }
function Step { param($m) Write-Host ("`n== " + $m) -ForegroundColor Cyan }
function Ok   { param($m) Write-Host ("   [OK] " + $m) -ForegroundColor Green }
function Warn { param($m) Write-Host ("   [!]  " + $m) -ForegroundColor Yellow }
function Bad  { param($m) Write-Host ("   [X]  " + $m) -ForegroundColor Red }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha { param($p) (Get-FileHash $p -Algorithm SHA256).Hash }

function Test-UuRunning {
    $r = @()
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            if ($p.Path -and $p.Path.StartsWith($InstallRoot, [StringComparison]::OrdinalIgnoreCase)) { $r += $p }
        } catch { }
    }
    return , $r
}

function Stop-UuAll {
    $r = Test-UuRunning
    if ($r.Count -eq 0) { return $true }
    Warn ("UU 相关进程正在运行：" + (($r | ForEach-Object { $_.ProcessName + "(" + $_.Id + ")" }) -join ", "))
    try { Stop-Service GameViewerService -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Seconds 1
    foreach ($p in (Test-UuRunning)) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { } }
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 700
        if ((Test-UuRunning).Count -eq 0) { return $true }
    }
    return $false
}

function Copy-WithRetry {
    param([string]$Src, [string]$Dst, [int]$Tries = 20)
    for ($i = 0; $i -lt $Tries; $i++) {
        try { Copy-Item $Src $Dst -Force -ErrorAction Stop; return $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    return $false
}

function Restore-All {
    param([switch]$Offline)
    $did = $false
    if (Test-Path $DllStock) {
        if ($Offline) { [void](Stop-UuAll) }
        if (Copy-WithRetry $DllStock $Dll) {
            Remove-Item $DllStock -Force -ErrorAction SilentlyContinue
            $h = Get-Sha $Dll
            if ($h -eq $StockDllSha) { Ok "streamer.dll 已还原并校验通过" }
            else { Warn ("streamer.dll 还原后哈希不符: " + $h) }
        } else {
            Bad "无法还原 streamer.dll —— 文件仍被进程占用"
            Say  "       请完全退出 UU远程（请手动使用任务管理器，确保完全关闭），然后运行："
            Say  ("       powershell -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" -Restore")
        }
        $did = $true
    }
    if (Test-Path $DetStock) {
        if (Copy-WithRetry $DetStock $Detector) {
            Remove-Item $DetStock -Force -ErrorAction SilentlyContinue
            Ok "StreamerCodecDetector.exe 已还原"
        } else {
            Bad "无法还原 StreamerCodecDetector.exe"
        }
        $did = $true
    }
    return $did
}

Say ""
Say "  UU远程硬解解锁补丁"
Say "  ------------------------------------------------"

if (-not $SkipAdminCheck -and -not (Test-Admin)) {
    Bad "需要管理员权限。请以管理员身份运行 PowerShell 后重试。"
    exit 2
}

if ($Restore) {
    Step "手动还原..."
    if (Restore-All) { } else { Warn "未找到 .stock / .orig.exe 备份（你似乎未安装补丁）" }
    Say ""
    exit 0
}

Step "1/6  检查环境"
if (-not (Test-Path $Dll)) { Bad ("找不到 " + $Dll); exit 3 }
$cur = Get-Sha $Dll
Ok ("streamer.dll sha256=" + $cur.Substring(0, 16) + "...")

if ((Test-Path $DllStock) -or (Test-Path $DetStock)) {
    Warn "检测到上次运行非正常结束，正在自动还原 ..."
    Restore-All | Out-Null
    $cur = Get-Sha $Dll
    if ($cur -eq $StockDllSha) { Ok "残留已清理，streamer.dll 已还原" }
    else { Warn ("streamer.dll 仍不是原版：" + $cur.Substring(0, 16) + "...") }
}

if ($cur -ne $StockDllSha) {
    Bad "版本错误：streamer.dll 版本与本脚本适用版本不符。"
    Say ("       期望: " + $StockDllSha)
    Say ("       实际: " + $cur)
    exit 4
}

$bytes = [System.IO.File]::ReadAllBytes($Dll)
$at = $bytes[$PatchOffset..($PatchOffset + $PatchLen - 1)]
$okPatch = $true
for ($i = 0; $i -lt $PatchLen; $i++) { if ($at[$i] -ne $PatchOld[$i]) { $okPatch = $false } }
if (-not $okPatch) {
    Bad ("补丁失败：目标偏移 0x{0:X} 处的字节不是预期的 {1}（实际 {2}）" -f `
        $PatchOffset, (($PatchOld | ForEach-Object { $_.ToString("x2") }) -join " "), (($at | ForEach-Object { $_.ToString("x2") }) -join " "))
    exit 4
}
Ok ("补丁点校验通过（0x{0:X} = {1} / 默认返回值 mov eax,5）" -f $PatchOffset, (($PatchOld | ForEach-Object { $_.ToString("x2") }) -join " "))

$running = Test-UuRunning
if ($running.Count -gt 0 -and -not $NoPrompt) {
    Warn ("检测到 UU远程 相关进程正在运行：" + (($running | ForEach-Object { $_.ProcessName + "(" + $_.Id + ")" }) -join ", "))
    $ans = Read-Host "       脚本需要先结束这些进程，是否继续？(Y/N)"
    if ($ans -ne "Y" -and $ans -ne "y") { Bad "请手动退出 UU远程 后重试。"; exit 5 }
}
if (-not (Stop-UuAll)) {
    Bad "UU远程 进程仍在运行，无法继续。请完全退出 UU远程（请手动使用任务管理器，确保完全关闭）后重试。"
    exit 5
}
Ok "UU 未占用安装目录"

# ------------------------------------------------------------------ 2 补丁
$restored = $false
try {
    Step "2/6  补丁 streamer.dll"
    Copy-Item $Dll $DllStock -Force
    Ok "已备份为 streamer.dll.stock"

    $bytes = [System.IO.File]::ReadAllBytes($DllStock)
    [Array]::Copy($PatchNew, 0, $bytes, $PatchOffset, $PatchLen)
    [System.IO.File]::WriteAllBytes($Dll, $bytes)

    $chk = [System.IO.File]::ReadAllBytes($Dll)[$PatchOffset..($PatchOffset + $PatchLen - 1)]
    $okW = $true
    for ($i = 0; $i -lt $PatchLen; $i++) { if ($chk[$i] -ne $PatchNew[$i]) { $okW = $false } }
    if ($okW) {
        Ok ("补丁已写入（0x{0:X} = {1}，未知厂商 class 5 -> class 2）" -f $PatchOffset, (($chk | ForEach-Object { $_.ToString("x2") }) -join " "))
    } else {
        Bad "补丁写入后校验失败，正在还原"; Restore-All; exit 6
    }

    # -------------------------------------------------------------- 3 替身
    Step "3/6  安装GPU探测器"
    $shimB64 = @'
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFt
IGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDABBtw2oAAAAAAAAAAOAAAgELAQsAABoAAAAIAAAAAAAA7jkAAAAgAAAAQAAA
AABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAJg5AABTAAAAAEAAAPAE
AAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAA
CCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAA9BkAAAAgAAAAGgAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAPAEAAAAQAAAAAYAAAAcAAAAAAAAAAAAAAAA
AABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAIgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAADQOQAAAAAAAEgAAAACAAUA3CoAALwOAAABAAAA
AQAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMwBQCvAwAAAQAAESgEAAAKbwUAAAoKBigGAAAKCygHAAAKcgEA
AHAoCAAACgwCjmkaMhACFppyKwAAcBsoCQAACi0scjsAAHAoCgAACigLAAAKbwwAAAoIcsYAAHACKAcAAAYoDQAACigIAAAGFyoVDRUTBAIXmhIDKA4AAAom
AhiaEgQoDgAACiYIHI0BAAABExMRExZy2AAAcKIRExcJjAwAAAGiERMYcvAAAHCiERMZEQSMDAAAAaIRExpy/AAAcKIRExsCjmmMDAAAAaIREygPAAAKKAgA
AAZyCgEAcCgQAAAKEwURBSgRAAAKLA0HciABAHAoCAAAChMFILgLAAATBnJeAQBwKBAAAAoTCBEIKBEAAAotFBEIEgcoDgAACiwJEQcWMQQRBxMGEQUHAhEG
EgkoBgAABhMKCR8g/gETCxELOVMBAAARCSgFAAAGEwwWEw0WEw44swAAABuNCAAAARMUERQWfgEAAAQRDhYoEgAACqIRFBdygAEAcKIRFBh+AQAABBEOFygS
AAAKohEUGXKAAQBwohEUGn4BAAAEEQ4YKBIAAAqiERQoEwAAChMPFBMQEQwRDxIRbxQAAAosBBERExARECgEAAAGLRcRDigCAAAGKAQAAAYsCREOKAIAAAYT
EBEQLQkRDigDAAAGExARECgEAAAGLAYRDRdYEw0RECgKAAAKEQ4XWBMOEQ5+AQAABBZvFQAACj87////coQBAHAoCgAACigLAAAKbwwAAAoIHo0BAAABExUR
FRZymgEAcKIRFRcJjAwAAAGiERUYcvAAAHCiERUZEQSMDAAAAaIRFRpypgEAcKIRFRsRCowPAAABohEVHHLEAQBwohEVHRENjAwAAAGiERUoDwAACigIAAAG
FioRCjmBAAAAEQlyhAEAcBpvFgAAChYycREJKBcAAAooCwAACm8MAAAKCB2NAQAAARMWERYWcpoBAHCiERYXCYwMAAABohEWGHLwAABwohEWGREEjAwAAAGi
ERYactgBAHCiERYbEQlvGAAACowMAAABohEWHHLuAQBwohEWKA8AAAooCAAABhYqFhMSKxIREigDAAAGKAoAAAoREhdYExIREn4BAAAEFm8VAAAKMt9yhAEA
cCgKAAAKKAsAAApvDAAACggdjQEAAAETFxEXFnKaAQBwohEXFwmMDAAAAaIRFxhy8AAAcKIRFxkRBIwMAAABohEXGnL8AQBwohEXGxEKjA8AAAGiERccchQC
AHCiERcoDwAACigIAAAGFioAEzAFAJwAAAACAAARHwyNCAAAAQoGFnIoAgBwogYXfgEAAAQCFigSAAAKogYYcoABAHCiBhl+AQAABAIXKBIAAAqiBhpygAEA
cKIGG34BAAAEAhgoEgAACqIGHHKAAQBwogYdfgEAAAQCGSgSAAAKogYecoABAHCiBh8JfgEAAAQCGigSAAAKogYfCnKAAQBwogYfC34BAAAEAhsoEgAACqIG
KBMAAAoqEzAFAFsAAAACAAARHY0IAAABCgYWcigCAHCiBhd+AQAABAIWKBIAAAqiBhhygAEAcKIGGX4BAAAEAhcoEgAACqIGGnKAAQBwogYbfgEAAAQCGCgS
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
BgClAxcBBgDUA7IBCgDgAxoDCgB9BBoDBgAWBTEABgAzBf0CAAAAAAEAAAAAAAEAAQCAARAAGwAAAAUAAQABAAMBEADqAgAABQADAAsAMQA/AAoAEQB+AyYB
BgAXAxQBUCAAAAAAkQBGABMAAQAMJAAAAACRAEsAGQACALQkAAAAAJEAVQAZAAMAHCUAAAAAkQBeAB4ABABkJQAAAACRAJIAIwAFAEQmAAAAAJEAnwAtAAYA
gCcAAAAAkQCoADgACwAAKAAAAACRAK0APgAMAEEmAAAAAJEAVgMfAQ4AUCgAAAAAkRhTBaIBEAAdJgAAAACGGAgBRAAQACUmAAAAAIYAQwMYARAAAAABALEA
AAABALYAAAABALYAAAABALgAAAABAL0AAAABAMIAAAACAMcAAAADALEAAAAEAMsAAgAFANUAAAABALEAAAABAA4BAAACABMBAAABAFIDAAACAFQDAAABAFID
AAACAFQDGQAIAUQAIQAIAUgAKQAIAUQAMQCQAU0AMQClAVIAOQDBAVYAOQDSAVsAOQDeAV8AQQD+AWUAUQANAm0AUQAiAnIAWQAqAkQAQQAwAl8AYQA9AncA
QQAwAn4AaQBSAlYAQQBpAh4ADAB3AowAQQAwAjgAFAB7ApkAcQCNAqIAQQCfAqcAUQCnAm0AQQCtAq4AQQC9AtwAQQDDAlIAQQDIAuMAFAAIAUQAQQDWAvAA
FADhAvcACQAIAUQAoQAIAUQAkQDAA1IAiQDJAy8BqQDZAx4AiQAIAUQAsQAIAUQAsQDxAzUBsQD+AzUBsQAMBDoBsQAgBDoBsQA7BDoBsQBVBDoBsQBoBDUB
uQAIAUQAuQCFBD8BmQAIAUUBuQCTBEsBuQCqBEsBuQDABFEBuQDGBEQAuQDaBEQAuQDtBFUBuQDtBEQAuQD5BEQACQD+BFIAiQAHBWYBQQCfAmwBQQAOBXEB
iQAHBS8BwQAfBX4BwQD+BIMBaQAnBVsAQQAwAogByQA8BZABqQBFBZUBDAAIAaYBDABaBawBLgATAL0BLgAbAMYBQQADASoBYwADASoBIAEDASoBsgDXAOkA
/wBaAXcBnQGzAYQAkgAEgAAAAAAAAAAAAAAAAAAAAAAbAAAABAAAAAAAAAAAAAAAAQAoAAAAAAAEAAAAAAAAAAAAAAABADEAAAAAAAMAAgAAAAA8TW9kdWxl
PgBEZXRlY3RvclNoaW0uZXhlAERldGVjdG9yU2hpbQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AE1hdHJpeABNYWluAEZsb29yTGluZQBaZXJvTGluZQBJc1N1
cHBvcnRlZABTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBEaWN0aW9uYXJ5YDIAUGFyc2VSZXN1bHRzAFJ1bkNoaWxkAEpvaW4ATG9nAGFyZ3MAaQBsaW5l
AHRleHQAb3JpZwBkaXIAdGltZW91dE1zAG91dHB1dABTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAT3V0QXR0cmlidXRlAC5jdG9yAHBhdGgAbXNn
AFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJp
YnV0ZQBTeXN0ZW0uUmVmbGVjdGlvbgBBc3NlbWJseQBHZXRFeGVjdXRpbmdBc3NlbWJseQBnZXRfTG9jYXRpb24AU3lzdGVtLklPAFBhdGgAR2V0RGlyZWN0
b3J5TmFtZQBHZXRUZW1wUGF0aABDb21iaW5lAFN0cmluZwBTdHJpbmdDb21wYXJpc29uAEVxdWFscwBDb25zb2xlAFdyaXRlTGluZQBUZXh0V3JpdGVyAGdl
dF9PdXQARmx1c2gAQ29uY2F0AEludDMyAFRyeVBhcnNlAEVudmlyb25tZW50AEdldEVudmlyb25tZW50VmFyaWFibGUASXNOdWxsT3JFbXB0eQBHZXQAVHJ5
R2V0VmFsdWUAQXJyYXkAR2V0TGVuZ3RoAEJvb2xlYW4ASW5kZXhPZgBXcml0ZQBnZXRfTGVuZ3RoAENoYXIAU3BsaXQAVHJpbQBvcF9JbmVxdWFsaXR5AFN0
YXJ0c1dpdGgAc2V0X0l0ZW0APD5jX19EaXNwbGF5Q2xhc3M0AFN5c3RlbS5UZXh0AFN0cmluZ0J1aWxkZXIAc2IAU3lzdGVtLkRpYWdub3N0aWNzAERhdGFS
ZWNlaXZlZEV2ZW50QXJncwA8UnVuQ2hpbGQ+Yl9fMABzAGUAPFJ1bkNoaWxkPmJfXzEARGF0YVJlY2VpdmVkRXZlbnRIYW5kbGVyAENTJDw+OV9fQ2FjaGVk
QW5vbnltb3VzTWV0aG9kRGVsZWdhdGUzAENvbXBpbGVyR2VuZXJhdGVkQXR0cmlidXRlAGdldF9EYXRhAEFwcGVuZExpbmUARmlsZQBFeGlzdHMAUHJvY2Vz
c1N0YXJ0SW5mbwBzZXRfRmlsZU5hbWUAc2V0X0FyZ3VtZW50cwBzZXRfVXNlU2hlbGxFeGVjdXRlAHNldF9SZWRpcmVjdFN0YW5kYXJkT3V0cHV0AHNldF9S
ZWRpcmVjdFN0YW5kYXJkRXJyb3IAc2V0X0NyZWF0ZU5vV2luZG93AHNldF9Xb3JraW5nRGlyZWN0b3J5AFByb2Nlc3MAc2V0X1N0YXJ0SW5mbwBhZGRfT3V0
cHV0RGF0YVJlY2VpdmVkAGFkZF9FcnJvckRhdGFSZWNlaXZlZABTdGFydABCZWdpbk91dHB1dFJlYWRMaW5lAEJlZ2luRXJyb3JSZWFkTGluZQBXYWl0Rm9y
RXhpdABLaWxsAFRvU3RyaW5nAEFwcGVuZABSZXBsYWNlAERhdGVUaW1lAGdldF9Ob3cAZ2V0X05ld0xpbmUARW5jb2RpbmcAZ2V0X1VURjgAQXBwZW5kQWxs
VGV4dAAuY2N0b3IAU2V0AAAAACl1AHUAXwBkAGUAdABlAGMAdABvAHIAXwBzAGgAaQBtAC4AbABvAGcAAA8tAC0AYgBhAHQAYwBoAAGAiVUAcwBhAGcAZQA6
ACAAUwB0AHIAZQBhAG0AZQByAEMAbwBkAGUAYwBEAGUAdABlAGMAdABvAHIAIAAtAC0AYgBhAHQAYwBoACAAPABpAG0AcABsAD4AIAA8AGQAZQB2AGkAYwBl
AF8AaQBkAD4AIAA8AGEAZABhAHAAdABlAHIAXwBpAGQAPgABEUIAQQBEAEEAUgBHAFMAIAAAF0UATgBUAEUAUgAgAGkAbQBwAGwAPQAACyAAZABlAHYAPQAA
DSAAYQByAGcAYwA9AAAVVQBVAEQARQBUAF8ATwBSAEkARwAAPVMAdAByAGUAYQBtAGUAcgBDAG8AZABlAGMARABlAHQAZQBjAHQAbwByAC4AbwByAGkAZwAu
AGUAeABlAAAhVQBVAEQARQBUAF8AVABJAE0ARQBPAFUAVABfAE0AUwAAAywAABVCAEEAVABDAEgAXwBEAE8ATgBFAAALaQBtAHAAbAA9AAAdIABoAHcAIABj
AGgAaQBsAGQARABvAG4AZQA9AAATIABuAG8AbgB6AGUAcgBvAD0AABUgAHYAZQByAGIAYQB0AGkAbQAgAAANIABjAGgAYQByAHMAABcgAGMAaABpAGwAZABE
AG8AbgBlAD0AABMgAC0APgAgAHoAZQByAG8AcwABD1IARQBTAFUATABUACwAAA0sADAALAAwACwAMAAAAzAAAAEAAyIAAAVcACIAAC95AHkAeQB5AC0ATQBN
AC0AZABkACAASABIADoAbQBtADoAcwBzAC4AZgBmAGYAAQMgAAADMQAAAzgAAAkzADgANAAwAAAJMgAxADYAMAAABTEAMAAAAzMAAAMyAADTRpU4SO2gTZUb
4tWfkteNAAi3elxWGTTgiQgGFA4CAAIAAAUAAQgdDgQAAQ4IBAABAg4JAAEVEgkCDg4OCgAFAg4OHQ4IEA4FAAEOHQ4FAAIBDg4DIAABBCABAQgEAAASGQMg
AA4EAAEODgMAAA4FAAIODg4HAAMCDg4RJQQAAQEOBAAAEi0GAAICDhAIBQABDh0cBxQOAgACAAAFIAIOCAgGFRIJAg4OCCACAhMAEBMBBCABCAgGIAIIDhEl
AyAACCQHGA4ODggIDggIDg4CAhUSCQIODggIDg4OCB0cHQ4dHB0cHRwEBwEdDgYgAR0OHQMFAAICDg4GBwIdDh0DBiACAg4RJQcgAgETABMBFAcIFRIJAg4O
HQ4IDh0OHQMdAx0OAwYSRQYgAgEcEkkGAAIBHBJJAwYSTQQBAAAABSABEkUOBCABAQ4EIAEBAgUgAQESWQUgAgEcGAUgAQESTQMgAAIEIAECCAsHBQISWRJd
Ek0SDAUgARJFAwQgAQgDBSACDg4OBgcDEkUIDgQAABFhBCABDg4HAAQODg4ODgQAABJlBwADAQ4OEmUEBwERYQMAAAEFIAIBCAgGIAMBCAgOCQcBFA4CAAIA
AAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEAAADAOQAAAAAAAAAAAADeOQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0DkAAAAA
AAAAAAAAAAAAAAAAX0NvckV4ZU1haW4AbXNjb3JlZS5kbGwAAAAAAP8lACBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAQAAAAIAAAgBgAAAA4AACA
AAAAAAAAAAAAAAAAAAABAAEAAABQAACAAAAAAAAAAAAAAAAAAAABAAEAAABoAACAAAAAAAAAAAAAAAAAAAABAAAAAACAAAAAAAAAAAAAAAAAAAAAAAABAAAA
AACQAAAAoEAAAFwCAAAAAAAAAAAAAABDAADqAQAAAAAAAAAAAABcAjQAAABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAAA
AAAAAAAAAAAAAAAAPwAAAAAAAAAEAAAAAQAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAbgBzAGwA
YQB0AGkAbwBuAAAAAAAAALAEvAEAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAmAEAAAEAMAAwADAAMAAwADQAYgAwAAAALAACAAEARgBpAGwA
ZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAABEABEAAQBJAG4A
dABlAHIAbgBhAGwATgBhAG0AZQAAAEQAZQB0AGUAYwB0AG8AcgBTAGgAaQBtAC4AZQB4AGUAAAAAACgAAgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgA
dAAAACAAAABMABEAAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwAZQBuAGEAbQBlAAAARABlAHQAZQBjAHQAbwByAFMAaABpAG0ALgBlAHgAZQAAAAAANAAIAAEA
UAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAwAC4A
MAAuADAALgAwAAAAAAAAAO+7vzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz4NCjxhc3NlbWJseSB4bWxu
cz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjEiIG1hbmlmZXN0VmVyc2lvbj0iMS4wIj4NCiAgPGFzc2VtYmx5SWRlbnRpdHkgdmVyc2lvbj0i
MS4wLjAuMCIgbmFtZT0iTXlBcHBsaWNhdGlvbi5hcHAiLz4NCiAgPHRydXN0SW5mbyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjIi
Pg0KICAgIDxzZWN1cml0eT4NCiAgICAgIDxyZXF1ZXN0ZWRQcml2aWxlZ2VzIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQog
ICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0iYXNJbnZva2VyIiB1aUFjY2Vzcz0iZmFsc2UiLz4NCiAgICAgIDwvcmVxdWVzdGVkUHJp
dmlsZWdlcz4NCiAgICA8L3NlY3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+DQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAMAAAA8DkAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
'@
    $shimB64 = ($shimB64 -replace "\s", "")
    $shimBytes = [Convert]::FromBase64String($shimB64)
    if ($shimBytes.Length -lt 1024) { Bad "内置数据异常"; exit 6 }
    Copy-Item $Detector $DetStock -Force
    [System.IO.File]::WriteAllBytes($Detector, $shimBytes)
    Ok ("已写入 {0} 字节" -f $shimBytes.Length)

    # -------------------------------------------------------------- 4 等待
    Step "4/6  等待 UU 远程写出解码能力缓存"
    Say ""
    Say "   请完成以下三步（请勿关闭本窗口）："
    Say "     1) 启动 UU 远程"
    Say "     2) 连接任意被控端，进入桌面画面并保持 30 秒以上"
    Say "     3) 连接成功后打开画质菜单，尝试切到「原画」或「超清」"
    Say ""
    Say ("   最多等待 {0} 分钟，缓存出现后，会立即还原文件。" -f $WaitMinutes)
    Say "   还原需要关闭 UU，在还原前请先结束正在进行的操作。"
    Say ""

    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $found = $false
    $tick = 0
    $shimCalls = 0
    if (Test-Path $ShimLog) { $shimCalls = @(Get-Content $ShimLog -ErrorAction SilentlyContinue).Count }
    Say ("   GPU探测器此前累计被调用 {0} 次。" -f $shimCalls)

    while ((Get-Date) -lt $deadline) {
        if (Test-Path $Cache) {
            Start-Sleep -Milliseconds 800
            try {
                $j = Get-Content $Cache -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($j.decoder_capabilities -and @($j.decoder_capabilities).Count -gt 0) { $found = $true; break }
            } catch { }
        }
        $tick++
        if (Test-Path $ShimLog) {
            $nowCalls = @(Get-Content $ShimLog -ErrorAction SilentlyContinue).Count
            if ($nowCalls -gt $shimCalls) {
                $shimCalls = $nowCalls
                Write-Host ("   >>> GPU探测器被调用（累计 {0} 次）。UU 正在探测：{1}" -f $nowCalls, (Get-Content $ShimLog -Tail 1)) -ForegroundColor Green
            }
        }
        if ($tick % 10 -eq 0) {
            Write-Host ("   ... 等待中，剩余 {0} 秒" -f [int](($deadline - (Get-Date)).TotalSeconds))
        }
        Start-Sleep -Seconds 1
    }

    # -------------------------------------------------------------- 5 还原
    Step "5/6  还原文件"
    Say "   需先关闭 UU 才能还原（会断开当前远程会话）。"
    Restore-All -Offline | Out-Null
    $restored = $true

    # -------------------------------------------------------------- 6 结果
    Step "6/6  结果"
    if ($found) {
        Ok "修复完成。UU已生成解码能力缓存。"
        Say ""
        $j = Get-Content $Cache -Raw -Encoding UTF8 | ConvertFrom-Json
        Say ("   文件     : " + $Cache)
        Say ("   version  : " + $j.version)
        Say ("   指纹     : " + $j.gpu_fingerprint)
        Say ("   条目数   : " + @($j.decoder_capabilities).Count)
        Say  "   硬件条目 :"
        $impl = @{ 32 = "DXVA11"; 33 = "NvDec"; 34 = "VideoToolbox"; 35 = "AsyncMediaCodec"; 36 = "SyncMediaCodec"; 37 = "Software" }
        foreach ($c in (@($j.decoder_capabilities) | Where-Object { $_.codec_impl -ne 37 })) {
            $cn = if ($c.video_codec -eq 1) { "H.264" } else { "H.265" }
            $res = if ($c.width -eq 0) { "任意尺寸" } else { "$($c.width)x$($c.height)" }
            $im = if ($impl.ContainsKey([int]$c.codec_impl)) { $impl[[int]$c.codec_impl] } else { $c.codec_impl }
            Say ("     {0}  chroma={1} {2}bit  {3}  {4}" -f $cn, $c.chroma_sampling, $c.bit_depth, $res, $im)
        }
        Say ""
        Say "   接下来请断开远程会话，重新连接，尝试选「原画」或「超清」。"
    } else {
        Bad ("等待 {0} 分钟仍未生成缓存。" -f $WaitMinutes)
        Say ""
        Say "   排查："
        Say "     · 确认已经连接了被控端（进入桌面画面）"
        Say "     · GPU探测器日志： " + $ShimLog
        Say "     · 若探测器调用次数为 0，说明补丁仍未生效，请在GitHub上提交issue反馈。（https://github.com/eggylan/uu-remote-gpu-unlock/issues）"
        Say "     · 可用更长时间重试： -WaitMinutes 30"
    }
    if (Test-Path $ShimLog) {
        Say ""
        Say "   GPU探测器日志（尾部 10 行）："
        Get-Content $ShimLog -Tail 10 | ForEach-Object { Say ("     " + $_) }
    }
}
finally {
    if (-not $restored) {
        Say ""
        Warn "正在强制还原 ..."
        try { Restore-All -Offline | Out-Null }
        catch { Bad ("强制还原失败：" + $_.Exception.Message); Say "       请完全退出 UU 后运行： ...\uu-remote-patcher.ps1 -Restore" }
    }
}
Say ""
