[CmdletBinding()]
param(
    [string]$InstallDir  = "",
    [int]$WaitMinutes    = 15,
    [switch]$Restore,
    [switch]$NoPrompt,
    [switch]$DryRun,
    [switch]$KeepPatched,
    [switch]$SkipAdminCheck
)

$ErrorActionPreference = "Stop"


#  已知版本表
$KnownVersions = @{
    "2DB8630CB0D73B54135FF972AD82FC053FDEFF5117E67C5DD295EC4020C73276" = @{
        Version = "4.40.1.2090"
        Note    = "1 处"
        Sites   = @(0x9B172F)
    }
    "AB8ADE084C4F714FE5B21D1324B7E5D13E41BB036D4382E4BC231383B3D56E79" = @{
        Version = "4.42.0.2770"
        Note    = "6 处内联"
        Sites   = @(0x927A36, 0x927A73, 0x973E48, 0x9765C3, 0x9765F0, 0xB409CF)
    }
}

# 厂商分类器里的常量：NVIDIA / AMD / Intel，以及未知厂商的默认返回值
$VendorNvidia  = 0x10DE
$VendorAmd     = 0x1002
$VendorIntel   = 0x8086
$ClassUnknown  = 5
$ClassProbe    = 2

# mov r32, imm32 的编码（含 REX.B 形式）
$MovEncodings = @(
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBC); Reg = "r12d" }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBD); Reg = "r13d" }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBE); Reg = "r14d" }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBF); Reg = "r15d" }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xB8); Reg = "r8d"  }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xB9); Reg = "r9d"  }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBA); Reg = "r10d" }
    [pscustomobject]@{ Bytes = [byte[]](0x41, 0xBB); Reg = "r11d" }
    [pscustomobject]@{ Bytes = [byte[]](0xB8);       Reg = "eax"  }
    [pscustomobject]@{ Bytes = [byte[]](0xB9);       Reg = "ecx"  }
    [pscustomobject]@{ Bytes = [byte[]](0xBA);       Reg = "edx"  }
    [pscustomobject]@{ Bytes = [byte[]](0xBB);       Reg = "ebx"  }
    [pscustomobject]@{ Bytes = [byte[]](0xBD);       Reg = "ebp"  }
    [pscustomobject]@{ Bytes = [byte[]](0xBE);       Reg = "esi"  }
    [pscustomobject]@{ Bytes = [byte[]](0xBF);       Reg = "edi"  }
)

$Latin1 = [System.Text.Encoding]::GetEncoding(28591)

function Say  { param($m) Write-Host $m }
function Step { param($m) Write-Host ("`n== " + $m) -ForegroundColor Cyan }
function Ok   { param($m) Write-Host ("   [OK] " + $m) -ForegroundColor Green }
function Warn { param($m) Write-Host ("   [!] " + $m) -ForegroundColor Yellow }
function Bad  { param($m) Write-Host ("   [X] " + $m) -ForegroundColor Red }
function Info { param($m) Write-Host ("        " + $m) -ForegroundColor DarkGray }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha { param($p) (Get-FileHash $p -Algorithm SHA256).Hash }


#  PE 解析
function Get-PeInfo {
    param([byte[]]$Bytes)
    $e = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ([BitConverter]::ToUInt32($Bytes, $e) -ne 0x00004550) { throw "不是有效的 PE 文件" }
    $numSec = [BitConverter]::ToUInt16($Bytes, $e + 6)
    $optSz  = [BitConverter]::ToUInt16($Bytes, $e + 20)
    $magic  = [BitConverter]::ToUInt16($Bytes, $e + 24)
    if ($magic -eq 0x20B) {
        $imageBase = [BitConverter]::ToUInt64($Bytes, $e + 48)
    } else {
        $imageBase = [uint64][BitConverter]::ToUInt32($Bytes, $e + 52)
    }
    $secOff = $e + 24 + $optSz
    $secs = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $numSec; $i++) {
        $o = $secOff + $i * 40
        $secs.Add([pscustomobject]@{
            Name           = ([System.Text.Encoding]::ASCII.GetString($Bytes, $o, 8)).TrimEnd([char]0)
            VirtualAddress = [BitConverter]::ToUInt32($Bytes, $o + 12)
            RawSize        = [BitConverter]::ToUInt32($Bytes, $o + 16)
            RawPtr         = [BitConverter]::ToUInt32($Bytes, $o + 20)
        })
    }
    return [pscustomobject]@{ ImageBase = $imageBase; Sections = $secs }
}

function New-Needle {
    # ISO-8859-1 maps each byte to the char with the same code point, so a byte pattern
    # becomes a 1-byte-per-char search string that String::IndexOf can scan quickly.
    param([byte[]]$B)
    return $Latin1.GetString($B)
}

function Find-All {
    param([string]$Hay, [string]$Needle)
    $res = New-Object System.Collections.Generic.List[int]
    $i = 0
    while ($true) {
        $i = $Hay.IndexOf($Needle, $i, [System.StringComparison]::Ordinal)
        if ($i -lt 0) { break }
        $res.Add($i)
        $i++
    }
    return , $res
}

#  定位补丁点
function Find-PatchSites {
    param([byte[]]$Bytes)

    $pe   = Get-PeInfo $Bytes
    $text = $null
    foreach ($s in $pe.Sections) { if ($s.Name -eq ".text") { $text = $s; break } }
    if (-not $text) { throw "在 PE 里找不到 .text 节" }

    $len = [int][Math]::Min([int]$text.RawSize, $Bytes.Length - [int]$text.RawPtr)
    $seg = New-Object byte[] $len
    [Array]::Copy($Bytes, [int]$text.RawPtr, $seg, 0, $len)
    $hay = $Latin1.GetString($seg)

    $intel  = Find-All $hay (New-Needle @(0x86, 0x80, 0x00, 0x00))
    $nvidia = Find-All $hay (New-Needle @(0xDE, 0x10, 0x00, 0x00))
    $amd    = Find-All $hay (New-Needle @(0x02, 0x10, 0x00, 0x00))

    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($i in $intel) {
        if ($i -lt 2) { continue }

        $isCmp = $false
        if ($seg[$i - 2] -eq 0x81 -and $seg[$i - 1] -ge 0xF8 -and $seg[$i - 1] -le 0xFF) { $isCmp = $true }
        elseif ($seg[$i - 1] -eq 0x3D) { $isCmp = $true }
        if (-not $isCmp) { continue }

        $near = 0
        foreach ($x in $nvidia) { if ($i -gt $x -and ($i - $x) -le 64) { $near = $near -bor 1; break } }
        if (-not ($near -band 1)) { continue }
        $near = 0
        foreach ($x in $amd) { if ($i -gt $x -and ($i - $x) -le 64) { $near = $near -bor 1; break } }
        if (-not ($near -band 1)) { continue }

        $site = $null
        foreach ($want in @($ClassUnknown, $ClassProbe)) {
            for ($d = -16; $d -le 16 -and -not $site; $d++) {
                $o = $i + $d
                if ($o -lt 0 -or ($o + 6) -ge $len) { continue }
                foreach ($m in $MovEncodings) {
                    $enc = $m.Bytes
                    $same = $true
                    for ($k = 0; $k -lt $enc.Length; $k++) {
                        if ($seg[$o + $k] -ne $enc[$k]) { $same = $false; break }
                    }
                    if (-not $same) { continue }
                    $imm = $o + $enc.Length
                    if ($seg[$imm] -eq $want -and $seg[$imm + 1] -eq 0 -and
                        $seg[$imm + 2] -eq 0 -and $seg[$imm + 3] -eq 0) {
                        $site = [pscustomobject]@{
                            MovOff = [int]$text.RawPtr + $o
                            ImmOff = [int]$text.RawPtr + $imm
                            Reg    = $m.Reg
                            Value  = $want
                        }
                        break
                    }
                }
            }
            if ($site) { break }
        }
        if ($site) { $hits.Add($site) }
    }

    # 同一个偏移只保留一次
    $seen = @{}
    $res  = New-Object System.Collections.Generic.List[object]
    foreach ($s in $hits) {
        if (-not $seen.ContainsKey($s.ImmOff)) { $seen[$s.ImmOff] = $true; $res.Add($s) }
    }
    return , $res
}

function Show-Sites {
    param($Sites)
    Say ("       " + (($Sites | ForEach-Object { "0x{0:X}" -f $_.MovOff }) -join "  "))
}

# 读当前文件里各补丁点的字节
function Get-SiteBytes {
    param([byte[]]$Bytes, $Sites)
    $vals = New-Object System.Collections.Generic.List[int]
    foreach ($s in $Sites) { $vals.Add([int]$Bytes[$s.ImmOff]) }
    return , $vals
}

function Test-AllBytes {
    param($Vals, [int]$Want)
    foreach ($v in $Vals) { if ($v -ne $Want) { return $false } }
    return $true
}

#  安装目录探测
function Test-UuBin {
    param([string]$Path)
    if (-not $Path) { return $false }
    return (Test-Path (Join-Path $Path "streamer.dll") -PathType Leaf)
}

function Resolve-BinFromPath {
    param([string]$Path)
    if (-not $Path) { return $null }
    $p = $Path.Trim()
    if ($p.StartsWith('"')) {
        $e = $p.IndexOf('"', 1)
        if ($e -gt 1) { $p = $p.Substring(1, $e - 1) }
        else { $p = $p.Trim('"') }
    } elseif ($p -match '^[^"]*\s-') {
        $p = ($p -split '\s+')[0]
    } else {
        $p = $p.Trim('"')
        if ($p -match '^(.*),\d+$') { $p = $Matches[1].Trim('"') }
    }
    $p = [Environment]::ExpandEnvironmentVariables($p)

    if (Test-Path $p -PathType Leaf) {
        $leaf = Split-Path -Leaf $p
        if ($leaf -ieq "streamer.dll") { return (Split-Path -Parent $p) }
        $p = Split-Path -Parent $p
    }
    if (-not (Test-Path $p -PathType Container)) { return $null }

    foreach ($c in @($p, (Join-Path $p "bin"), (Join-Path $p "GameViewer\bin"))) {
        if (Test-UuBin $c) { return (Resolve-Path $c).Path }
    }
    return $null
}

$script:ProbeLog = New-Object System.Collections.Generic.List[string]

function Find-UuBin {
    param([string]$Hint)

    if ($Hint) {
        $r = Resolve-BinFromPath $Hint
        if ($r) { return [pscustomobject]@{ Bin = $r; Source = "参数 -InstallDir" } }
        return [pscustomobject]@{ Bin = $null; Source = "-InstallDir 指定的路径无效" }
    }

    $probes = New-Object System.Collections.Generic.List[object]

    # 服务注册
    try {
        $svcRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services")
        if ($svcRoot) {
            foreach ($n in $svcRoot.GetSubKeyNames()) {
                $k = $svcRoot.OpenSubKey($n)
                if (-not $k) { continue }
                try {
                    $ip = $k.GetValue("ImagePath")
                    if ($ip -and ($ip -match "GameViewer")) {
                        $probes.Add([pscustomobject]@{ Path = [string]$ip; Source = "服务 $n" })
                    }
                } finally { $k.Close() }
            }
            $svcRoot.Close()
        }
    } catch { }

    # 卸载注册表项
    foreach ($root in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) {
        foreach ($k in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { continue }
            if ($p.DisplayName -match "UU远程|GameViewer") {
                if ($p.DisplayIcon)      { $probes.Add([pscustomobject]@{ Path = [string]$p.DisplayIcon;      Source = "卸载项 $($k.PSChildName) / DisplayIcon" }) }
                if ($p.UninstallString)  { $probes.Add([pscustomobject]@{ Path = [string]$p.UninstallString;  Source = "卸载项 $($k.PSChildName) / UninstallString" }) }
                if ($p.InstallLocation)  { $probes.Add([pscustomobject]@{ Path = [string]$p.InstallLocation;  Source = "卸载项 $($k.PSChildName) / InstallLocation" }) }
            }
        }
    }

    # 正在运行的进程
    foreach ($pn in @("GameViewer", "GameViewerServer", "GameViewerService", "streamer")) {
        foreach ($pr in @(Get-Process -Name $pn -ErrorAction SilentlyContinue)) {
            try { if ($pr.Path) { $probes.Add([pscustomobject]@{ Path = (Split-Path -Parent $pr.Path); Source = "进程 $($pr.ProcessName)" }) } } catch { }
        }
    }

    # 网易自己的注册表键里任何像路径的值
    foreach ($root in @("HKLM:\SOFTWARE\Netease\GameViewer", "HKCU:\SOFTWARE\Netease\GameViewer")) {
        $p = Get-ItemProperty $root -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($v in $p.PSObject.Properties) {
            if ($v.Value -is [string] -and $v.Value -match "[:\\].*GameViewer") {
                $probes.Add([pscustomobject]@{ Path = $v.Value; Source = "$root\$($v.Name)" })
            }
        }
    }

    # 常见安装位置
    foreach ($d in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
        if (-not $d.Root) { continue }
        foreach ($rel in @("Netease\GameViewer", "Program Files\Netease\GameViewer",
                           "Program Files (x86)\Netease\GameViewer", "UU\GameViewer", "GameViewer")) {
            $probes.Add([pscustomobject]@{ Path = (Join-Path $d.Root $rel); Source = "常见路径" })
        }
    }
    if ($env:LOCALAPPDATA) { $probes.Add([pscustomobject]@{ Path = (Join-Path $env:LOCALAPPDATA "Netease\GameViewer"); Source = "常见路径" }) }
    if ($env:ProgramData)  { $probes.Add([pscustomobject]@{ Path = (Join-Path $env:ProgramData  "Netease\GameViewer"); Source = "常见路径" }) }

    foreach ($pr in $probes) {
        $r = Resolve-BinFromPath $pr.Path
        if ($r) { return [pscustomobject]@{ Bin = $r; Source = $pr.Source } }
        if ($pr.Path) { $script:ProbeLog.Add(("{0}  <- {1}" -f $pr.Path, $pr.Source)) }
    }
    return [pscustomobject]@{ Bin = $null; Source = $null }
}

#  进程与文件操作
function Test-UuRunning {
    $r = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        try {
            if ($p.Path -and $p.Path.StartsWith($script:InstallRoot, [StringComparison]::OrdinalIgnoreCase)) { $r += $p }
        } catch { }
    }
    return , $r
}

function Stop-UuAll {
    $r = Test-UuRunning
    if ($r.Count -eq 0) { return $true }
    Warn ("检测到 UU远程 正在运行：" + (($r | ForEach-Object { $_.ProcessName + "(" + $_.Id + ")" }) -join ", "))
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

# 还原后确认补丁点回到了5
function Test-RestoredDll {
    param([string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        $s = Find-PatchSites $b
        if ($s.Count -eq 0) { return $false }
        return (Test-AllBytes (Get-SiteBytes $b $s) $ClassUnknown)
    } catch { return $false }
}

function Test-BackupMatchesCurrent {
    param([string]$Backup, [string]$Current)
    try {
        $a = [System.IO.File]::ReadAllBytes($Backup)
        $b = [System.IO.File]::ReadAllBytes($Current)
        if ($a.Length -ne $b.Length) { return $false }
        $s = Find-PatchSites $b
        if ($s.Count -eq 0) { return $false }
        foreach ($x in $s) {
            $b[$x.ImmOff]     = $ClassUnknown
            $b[$x.ImmOff + 1] = 0
            $b[$x.ImmOff + 2] = 0
            $b[$x.ImmOff + 3] = 0
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $ha = [BitConverter]::ToString($sha.ComputeHash($a))
            $hb = [BitConverter]::ToString($sha.ComputeHash($b))
            return ($ha -eq $hb)
        } finally { $sha.Dispose() }
    } catch { return $false }
}

function Restore-All {
    param([switch]$Offline)
    $did = $false
    if (Test-Path $script:DllStock) {
        if ($Offline) { [void](Stop-UuAll) }
        if (Copy-WithRetry $script:DllStock $script:Dll) {
            Remove-Item $script:DllStock -Force -ErrorAction SilentlyContinue
            Remove-Item $script:KeepFlag -Force -ErrorAction SilentlyContinue
            if (Test-RestoredDll $script:Dll) {
                Ok "streamer.dll 已还原并校验通过"
            } else {
                Warn ("streamer.dll 已还原，但校验未通过（sha256=" + (Get-Sha $script:Dll).Substring(0, 16) + "...）")
            }
        } else {
            Bad "无法还原 streamer.dll：文件仍被进程占用"
            Say  "       请完全退出 UU远程（在任务管理器中确认已全部关闭），然后执行："
            Say  ("       powershell -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" -Restore")
        }
        $did = $true
    }
    if (Test-Path $script:DetStock) {
        if (Copy-WithRetry $script:DetStock $script:Detector) {
            Remove-Item $script:DetStock -Force -ErrorAction SilentlyContinue
            Ok "StreamerCodecDetector.exe 已还原"
        } else {
            Bad "无法还原 StreamerCodecDetector.exe"
        }
        $did = $true
    }
    return $did
}

# =====================================================================
Say "  ------------------------------------------------"
Say "  UU远程硬解解锁补丁 by EGGYLAN"
Say "  ------------------------------------------------"

if (-not $SkipAdminCheck -and -not $DryRun -and -not (Test-Admin)) {
    Bad "需要管理员权限，请以管理员身份运行 PowerShell。"
    exit 2
}

Step "1/6  定位 UU远程 安装目录"

$det = Find-UuBin $InstallDir
if (-not $det.Bin) {
    Bad "未能自动找到 UU远程 安装目录。"
    Say  ""
    Say  "   已尝试以下位置："
    foreach ($l in $script:ProbeLog) { Info $l }
    Say  ""
    Say  "   请手动指定（安装根目录 / bin 目录 / streamer.dll 路径均可）："
    Say  '       -InstallDir "D:\Netease\GameViewer"'
    exit 3
}

$script:InstallDir  = $det.Bin
$script:InstallRoot = Split-Path -Parent $script:InstallDir
$script:Dll         = Join-Path $script:InstallDir "streamer.dll"
$script:DllStock    = Join-Path $script:InstallDir "streamer.dll.stock"
$script:Detector    = Join-Path $script:InstallDir "StreamerCodecDetector.exe"
$script:DetStock    = Join-Path $script:InstallDir "StreamerCodecDetector.orig.exe"
$script:ConfigDir   = Join-Path $script:InstallRoot "config\streamer"
$script:Cache       = Join-Path $script:ConfigDir "decoder_codec_capability_cache.json"
$script:ShimLog     = Join-Path $env:TEMP "uu_detector_shim.log"
$script:KeepFlag    = Join-Path $script:InstallDir "uu-remote-keep.flag"

Ok ($script:InstallDir)
Info ("来源：" + $det.Source)
$uuVer = $null
try {
    $p = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GameViewer" -ErrorAction SilentlyContinue
    if ($p -and $p.DisplayVersion) { $uuVer = $p.DisplayVersion }
} catch { }
if ($uuVer) { Info ("UU " + $uuVer) }

if (-not (Test-Path $script:Dll)) { Bad ("找不到 " + $script:Dll); exit 3 }
if (-not (Test-Path $script:Detector)) { Warn ("找不到 " + $script:Detector + "（解码器探测器）") }

if ($Restore) {
    Step "还原为官方原版"
    if (Restore-All) { } else { Warn "未找到 .stock / .orig.exe 备份（你似乎未安装补丁）" }
    Say ""
    exit 0
}

Step "2/6  校验 streamer.dll"

$bytes = [System.IO.File]::ReadAllBytes($script:Dll)
$sha   = (Get-Sha $script:Dll)
Info ($bytes.Length.ToString() + " 字节   sha256 " + $sha.Substring(0, 16) + "...")

$sites = Find-PatchSites $bytes
if ($sites.Count -eq 0) {
    Bad "未能找到厂商分类代码，无法定位补丁点（文件可能已被修改）。"
    exit 4
}

$known = $null
if ($KnownVersions.ContainsKey($sha.ToUpper())) { $known = $KnownVersions[$sha.ToUpper()] }

if ($known) {
    Ok ("已识别版本 " + $known.Version + "（" + $known.Note + "）")
    $exp = @($known.Sites | Sort-Object)
    $act = @($sites | ForEach-Object { $_.MovOff } | Sort-Object)
    $same = ($exp.Count -eq $act.Count)
    if ($same) {
        for ($i = 0; $i -lt $exp.Count; $i++) { if ($exp[$i] -ne $act[$i]) { $same = $false; break } }
    }
    if (-not $same) {
        Bad "版本表与定位结果不一致，已中止执行。"
        Say ("       版本表：" + (($exp | ForEach-Object { "0x{0:X}" -f $_ }) -join " "))
        Say ("       实际值：" + (($act | ForEach-Object { "0x{0:X}" -f $_ }) -join " "))
        exit 4
    }
} else {
    Warn "不在已知版本表（UU远程可能已更新），将使用模式定位..."
}

Ok ("已定位 " + $sites.Count + " 个补丁点")
Show-Sites $sites

$curVals = Get-SiteBytes $bytes $sites

# 上次运行选择保留修改版
if (Test-Path $script:KeepFlag) {
    if (Test-AllBytes $curVals $ClassProbe) {
        Warn "已检测到补丁状态。未修改补丁文件，如需还原，请使用-Restore。"
        exit 0
    }
    Warn "保留标记已失效（UU远程可能已更新），继续执行。"
    Remove-Item $script:KeepFlag -Force -ErrorAction SilentlyContinue
}

# 上次运行中断
if ((Test-Path $script:DllStock) -or (Test-Path $script:DetStock)) {
    if ((Test-Path $script:DllStock) -and -not (Test-BackupMatchesCurrent $script:DllStock $script:Dll)) {
        Warn "备份与当前文件版本不一致（UU远程可能已更新），将跳过自动还原。"
        Move-Item $script:DllStock ($script:DllStock + ".old") -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $script:DllStock) -or (Test-Path $script:DetStock)) {
        Warn "检测到上次运行未正常结束，正在还原..."
        Restore-All | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes($script:Dll)
        if (Test-AllBytes (Get-SiteBytes $bytes $sites) $ClassUnknown) { Ok "残留已清理" }
        else { Bad "残留清理失败，请手动 -Restore"; exit 4 }
        $curVals = Get-SiteBytes $bytes $sites
    }
}

# 状态判定
if (Test-AllBytes $curVals $ClassProbe) {
    Warn "补丁已应用，且无备份可供还原（如需恢复官方版本，请重新安装 UU远程）。"
    exit 0
}
if (-not (Test-AllBytes $curVals $ClassUnknown)) {
    Bad "补丁点字节异常，文件可能已被其它工具修改。"
    Say ("       实际值：" + (($curVals | ForEach-Object { $_.ToString("x2") }) -join " "))
    exit 4
}
Ok "补丁点校验通过"

if ($DryRun) {
    Step "DryRun 预演"
    Ok "仅执行探测与校验，未修改任何文件。"
    Say ""
    exit 0
}

$running = Test-UuRunning
if ($running.Count -gt 0 -and -not $NoPrompt) {
    Warn ("检测到 UU远程 正在运行：" + (($running | ForEach-Object { $_.ProcessName + "(" + $_.Id + ")" }) -join ", "))
    $ans = Read-Host "       需先结束上述进程，是否继续？(Y/N)"
    if ($ans -ne "Y" -and $ans -ne "y") { Bad "请手动退出 UU远程 后重试。"; exit 5 }
}
if (-not (Stop-UuAll)) {
    Bad "UU远程 仍在运行，请完全退出后重试。"
    exit 5
}
Ok "安装目录未被占用"

$settled = $false
$keep    = $false
try {
    Step "3/6  应用补丁"
    Copy-Item $script:Dll $script:DllStock -Force
    Ok "已备份为 streamer.dll.stock"

    $bytes = [System.IO.File]::ReadAllBytes($script:DllStock)
    foreach ($s in $sites) {
        $bytes[$s.ImmOff]     = $ClassProbe
        $bytes[$s.ImmOff + 1] = 0
        $bytes[$s.ImmOff + 2] = 0
        $bytes[$s.ImmOff + 3] = 0
    }
    [System.IO.File]::WriteAllBytes($script:Dll, $bytes)

    $chk = [System.IO.File]::ReadAllBytes($script:Dll)
    if (Test-AllBytes (Get-SiteBytes $chk $sites) $ClassProbe) {
        Ok ("已写入 " + $sites.Count + " 处")
    } else {
        Bad "写入后校验未通过，正在还原"
        Restore-All
        exit 6
    }

    Step "4/6  安装探测器"
    $shimB64 = @'
__SHIM_B64__
'@
    $shimB64   = ($shimB64 -replace "\s", "")
    $shimBytes = [Convert]::FromBase64String($shimB64)
    if ($shimBytes.Length -lt 1024) { Bad "内置数据异常"; exit 6 }
    Copy-Item $script:Detector $script:DetStock -Force
    [System.IO.File]::WriteAllBytes($script:Detector, $shimBytes)
    Ok ("已写入 {0} 字节" -f $shimBytes.Length)

    Step "5/6  等待 UU 写出解码能力缓存"
    Say "   请启动 UU远程 主程序，并保持本窗口开启"
    Say ("   最长等待 {0} 分钟" -f $WaitMinutes)

    $deadline  = (Get-Date).AddMinutes($WaitMinutes)
    $found     = $false
    $tick      = 0
    $shimCalls = 0
    if (Test-Path $script:ShimLog) { $shimCalls = @(Get-Content $script:ShimLog -ErrorAction SilentlyContinue).Count }
    Info ("   探测器已调用 {0} 次" -f $shimCalls)

    while ((Get-Date) -lt $deadline) {
        if (Test-Path $script:Cache) {
            Start-Sleep -Milliseconds 800
            try {
                $j = Get-Content $script:Cache -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($j.decoder_capabilities -and @($j.decoder_capabilities).Count -gt 0) { $found = $true; break }
            } catch { }
        }
        $tick++
        if (Test-Path $script:ShimLog) {
            $nowCalls = @(Get-Content $script:ShimLog -ErrorAction SilentlyContinue).Count
            if ($nowCalls -gt $shimCalls) {
                $shimCalls = $nowCalls
                Write-Host ("   >>> GPU探测器被调用（累计 {0} 次）。UU 正在探测：{1}" -f $nowCalls, (Get-Content $script:ShimLog -Tail 1)) -ForegroundColor Green
            }
        }
        if ($tick % 10 -eq 0) {
            Write-Host ("   ... 等待中，剩余 {0} 秒" -f [int](($deadline - (Get-Date)).TotalSeconds))
        }
        Start-Sleep -Seconds 1
    }

    if ($found) { Step "6/6  解码缓存已生成，是否还原文件？" }
    else        { Step "6/6  未生成缓存，是否还原文件？" }

    $keep = $false
    if ($KeepPatched) {
        $keep = $true
        Warn "已指定 -KeepPatched，将保留补丁。"
    } elseif ($NoPrompt) {
        Say "   已指定 -NoPrompt，将按默认还原。"
    } else {
        Say "   [1] 还原为官方原版"
        Say "   [2] 保留补丁，不还原"
        $ans = Read-Host "   请输入 1 或 2"
        if ($ans -eq "2") { $keep = $true }
    }

    if ($keep) {
        [System.IO.File]::WriteAllText($script:KeepFlag,
            "keep`r`n", (New-Object System.Text.UTF8Encoding($false)))
        Ok "已保留补丁（如需还原，请使用-Restore）。"
        $settled = $true
    } else {
        Say "   还原需关闭 UU远程（将断开当前会话）"
        Restore-All -Offline | Out-Null
        $settled = $true
    }

    if ($found) {
        Ok "修复完成。UU远程 已生成解码能力缓存。"
        Say ""
        $j = Get-Content $script:Cache -Raw -Encoding UTF8 | ConvertFrom-Json
        Say ("       version " + $j.version + "   指纹 " + $j.gpu_fingerprint +
             "   条目 " + @($j.decoder_capabilities).Count)
        $impl = @{ 32 = "DXVA11"; 33 = "NvDec"; 34 = "VideoToolbox"; 35 = "AsyncMediaCodec"; 36 = "SyncMediaCodec"; 37 = "Software" }
        foreach ($c in (@($j.decoder_capabilities) | Where-Object { $_.codec_impl -ne 37 })) {
            $cn = if ($c.video_codec -eq 1) { "H.264" } else { "H.265" }
            $res = if ($c.width -eq 0) { "任意尺寸" } else { "$($c.width)x$($c.height)" }
            $im = if ($impl.ContainsKey([int]$c.codec_impl)) { $impl[[int]$c.codec_impl] } else { $c.codec_impl }
            Say ("       {0}  chroma={1} {2}bit  {3}  {4}" -f $cn, $c.chroma_sampling, $c.bit_depth, $res, $im)
        }
        Say ""
        if ($keep) { Say "   当前状态：已保留补丁" }
        else       { Say "   当前状态：已还原为官方原版" }
    } else {
        Bad ("等待 {0} 分钟仍未生成缓存" -f $WaitMinutes)
        Say "   请确认已启动 UU远程 主程序（无需连接被控端）"
        Say "   若探测器调用次数为 0，说明补丁未生效，请提交 issue："
        Say "     https://github.com/eggylan/uu-remote-gpu-unlock/issues"
        Say ("   探测器日志：" + $script:ShimLog)
        Say "   可延长等待时间： -WaitMinutes 30"
        Say ""
        if ($keep) { Say "   当前状态：已保留补丁（如需还原，请使用-Restore）" }
        else       { Say "   当前状态：已还原为官方原版" }
    }
    if (-not $found -and (Test-Path $script:ShimLog)) {
        Say ""
        Say "   探测器日志（尾部 10 行）："
        Get-Content $script:ShimLog -Tail 10 | ForEach-Object { Say ("     " + $_) }
    }
}
finally {
    if (-not $settled -and -not $keep) {
        Say ""
        Warn "正在还原 ..."
        try { Restore-All -Offline | Out-Null }
        catch {
            Bad ("还原失败：" + $_.Exception.Message)
            Say "       请完全退出 UU远程 后执行： -Restore"
        }
    }
}
Say ""
