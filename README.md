# UU远程 硬解解锁补丁

使UU远程（网易 GameViewer）在 **非 NVIDIA / AMD / Intel GPU** （例如Qualcomm Adreno、摩尔线程等）的机器上启用硬件解码，解锁高清和原画画质。

---

## 快速开始

**安装补丁：**

```powershell
# 1. 完全退出 UU（含托盘图标）
# 2. 以管理员身份打开 PowerShell，切换至 patch 目录
cd <本仓库>\patch
# 3. 运行
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1
```

按照脚本指示操作即可。

如需手动指定安装路径，使用 `-InstallDir` ：

```powershell
# 下面三种写法均可
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1 -InstallDir "D:\Netease\GameViewer"
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1 -InstallDir "D:\Netease\GameViewer\bin"
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1 -InstallDir "D:\Netease\GameViewer\bin\streamer.dll"
```

如需运行Dry Run：

```powershell
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1 -DryRun
```

**回滚**：

```powershell
powershell -ExecutionPolicy Bypass -File .\uu-remote-patcher.ps1 -Restore
```

如果运行过程中产生异常，脚本会自动还原。

### 参数

| 参数 | 说明 |
|---|---|
| `-InstallDir <路径>` | 手动指定 UU 安装位置 |
| `-Restore` | 还原为官方原版 |
| `-DryRun` | 仅校验，不修改任何文件 |
| `-WaitMinutes <n>` | 等待 UU 写出解码缓存的分钟数，默认 15 |
| `-NoPrompt` | 不询问，直接结束占用安装目录的 UU 进程 |
| `-KeepPatched` | 保留补丁 |
| `-SkipAdminCheck` | 跳过管理员权限检查 |

## 原理

### 问题

被控端画质菜单里选「原画」被拒绝，提示类似：

```
设备性能受限，最高支持高清画质
```

远控画质模糊，同时出现严重的设备发热和卡顿。

在**被控端**机器上可以观察到两个特征：

| 观察点 | 正常机器 | 异常机器 |
|---|---|---|
| `<UU>\config\streamer\decoder_codec_capability_cache.json` | 存在 | 目录为空 |
| `<UU>\bin\StreamerCodecDetector.exe` 是否被调用过 | 有 | 无 |

### 原因

`streamer.dll` 里有一个硬编码GPU厂商的小函数：

```asm
cmp  ecx, 0x10DE        ; NVIDIA：xor eax,eax ; ret
cmp  ecx, 0x1002        ; AMD：mov eax,1   ; ret
cmp  ecx, 0x8086        ; Intel：mov edx,2 ; cmove eax,edx ; ret
mov  eax, 5             ; 其它厂商：5
```

调用方在统计可探测适配器时会跳过 class 5：

```c
if (nodeClass != 5) { count += node.entries; }
...
if (!count) goto LABEL_67;
```

不在这张名单里的GPU计数为0，导致UU使用软解。

**受影响范围**：Qualcomm Adreno、Apple、其它国产 GPU，以及一切ACPI枚举而非PCI枚举的板载显卡

**也就是说，只要你的显卡不是 NVIDIA / AMD / Intel，几乎肯定中招。**


### 原理

#### 1. 白名单补丁

把厂商分类代码里的默认返回值从 `5` 改为 `2`（Intel / DXVA11 类）：

```
b8 05 00 00 00  (mov eax, 5)  ->  b8 02 00 00 00  (mov eax, 2)
```

#### 2. GPU探测器

替代原版的`StreamerCodecDetector.exe`，强制返回 `BATCH_DONE` ，并用基线表补全。

##### 基线表

```
H.264 4:2:0 8-bit  @4K     支持
H.265 4:2:0 8-bit  @4K     支持
H.265 4:2:0 10-bit @4K     支持
4:4:4（两种）、H.264 10-bit     不支持
```

合并时会取并集，以真实结论优先，基线表只补全缺失部分，因此不用担心会出现“硬件支持但不可用”的情况。这对任何GPU都生效。

#### 3. 结果

UU计算出 GPU 指纹、写出 `decoder_codec_capability_cache.json`，然后脚本把两个文件都还原成
原版。缓存里会包含该 GPU 真实的硬解能力，例如：

```
H.264 4:2:0 8bit  3840x2160  DXVA11
H.265 4:2:0 8bit  3840x2160  DXVA11
H.265 4:2:0 10bit 3840x2160  DXVA11
```

### 注意事项

- UU升级会覆盖回原版DLL，届时重新运行补丁即可（脚本会自动重新定位补丁点）。
- **解锁硬解不等于绝对没问题。** 如果解锁后出现卡顿、花屏、掉帧，说明GPU可能不兼容。还原补丁并删除 `<UU>\config\streamer\decoder_codec_capability_cache.json` 来回滚到软解。

### 已确认可用的版本

| UU 远程 | `streamer.dll` SHA256 | 补丁点 | 验证机 |
|---|---|---|---|
| GameViewer **4.42.0.2770** | `AB8ADE084C4F714FE5B21D1324B7E5D13E41BB036D4382E4BC231383B3D56E79` | `0x927A36` `0x927A73` `0x973E48` `0x9765C3` `0x9765F0` `0xB409CF` | Qualcomm Adreno 8cx Gen 3 |
| GameViewer **4.40.1.2090** | `2DB8630CB0D73B54135FF972AD82FC053FDEFF5117E67C5DD295EC4020C73276` | `0x9B172F` | Qualcomm Adreno 8cx Gen 3 |

不保证对后续版本的兼容性。如遇到问题，请提交Issue。

## 构建

```powershell
powershell -ExecutionPolicy Bypass -File .\build-shim.ps1
powershell -ExecutionPolicy Bypass -File .\make-deliverable.ps1
```

## 问题反馈

Issue 地址：https://github.com/eggylan/uu-remote-gpu-unlock/issues

请附上：

- `%TEMP%\uu_detector_shim.log`
- 脚本运行窗口的完整输出
- 显卡型号与 `DXGI_ADAPTER_DESC1` 的 `VendorId` / `DeviceId`

## 友情链接

- [LINUX DO - 新的理想型社区](https://linux.do/)

## 许可与免责声明

- 本仓库以 **CC0 1.0 Universal** 发布，见 `LICENCE`。可自由使用、修改、再分发，无需署名。
- 本仓库与网易/UU远程官方无关，没有隶属关系，亦未获其授权或认可。
- 补丁会修改 `streamer.dll` 中厂商分类代码的几个立即数字节，仅出于互操作目的，便于在官方未支持的硬件上使用。UU远程及其组件的版权归网易公司所有，本仓库不包含任何UU远程的二进制文件。
- 本仓库仅供学习与研究。使用风险自负，请自行确保符合你所在地区的法律与软件许可条款。
