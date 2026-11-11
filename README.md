# UU远程 硬解解锁补丁

使UU远程（网易 GameViewer）在 **非 NVIDIA / AMD / Intel GPU** （例如Qualcomm Adreno、摩尔线程、寒武纪等）的机器上启用硬件解码，解锁高清和原画画质。

---

## 快速开始

**安装补丁：**

```powershell
# 1. 完全退出 UU（含托盘图标）
# 2. 从Github下载或克隆仓库，以管理员身份打开 PowerShell，切换至 patch 目录
git clone --depth 1 https://github.com/eggylan/uu-remote-gpu-unlock.git
cd uu-remote-gpu-unlock\patch
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

| 参数                 | 说明                                   |
| -------------------- | -------------------------------------- |
| `-InstallDir <路径>` | 手动指定 UU 安装位置                   |
| `-Restore`           | 还原为官方原版                         |
| `-DryRun`            | 仅校验，不修改任何文件                 |
| `-WaitMinutes <n>`   | 等待 UU 写出解码缓存的分钟数，默认 15  |
| `-NoPrompt`          | 不询问，直接结束占用安装目录的 UU 进程 |
| `-KeepPatched`       | 保留补丁                               |
| `-SkipAdminCheck`    | 跳过管理员权限检查                     |

## 原理

### 问题

被控端画质菜单里选「原画」被拒绝，提示类似：

```
设备性能受限，最高支持高清画质
```

远控画质模糊，并伴随严重的设备发热和卡顿。

在**被控端**机器上可以观察到几个特征：

| 观察点                                                     | 正常机器     | 异常机器                |
| ---------------------------------------------------------- | ------------ | ----------------------- |
| `<UU>\config\streamer\decoder_codec_capability_cache.json` | 存在         | 不存在                  |
| `<UU>\config\streamer\encoder_codec_capability_cache.json` | 有硬编时存在 | 不存在                  |
| `<UU>\bin\StreamerCodecDetector.exe` 是否被调用过          | 有           | 无，或只被调用0次就结束 |

### 原因

在 `streamer.dll` 内部，存在一个硬编码的 GPU 硬件厂商识别函数。该函数通过比对 PCI Vendor ID 返回对应的厂商标识符：

```asm
cmp  ecx, 0x10DE        ; NVIDIA：xor eax,eax ; ret -> 返回 0
cmp  ecx, 0x1002        ; AMD：   mov eax,1   ; ret -> 返回 1
cmp  ecx, 0x8086        ; Intel： mov edx,2   ; cmove eax,edx ; ret -> 返回 2
mov  eax, 5             ; 其他未知厂商：返回 5
```

在后续的处理逻辑中，该返回值被直接复用为编解码器后端的类型标识（`0` 对应 NvEnc，`1` 对应 AMF，`2` 对应 QSV，`5` 对应软件编解码）。

在执行硬件解码能力探测（Probe）时，程序会遍历系统中的显示设备节点。若设备被归类为“未知厂商”（即标识符为 `5`），探测函数将直接跳过该节点：

```c
v13 = node->class;
if (v13 == 5) goto NEXT_NODE; // 未知厂商设备直接跳过检测
if (!flag_dxva) { count += node->entries; }
...
if (!count) return;
```

探测任务的分发严格依赖上述标识符：所有非 `5` 的设备节点均会被分配通用的 DXVA11（`impl 32`）探测任务；同时，标识符为 `0`、`1`、`2` 的节点会分别额外分配各自的专有硬件加速探测任务，即 NvDec（`impl 33`）、AMF（`impl 38`）与 oneVPL（`impl 39`）。

受此逻辑限制，非上述三大厂商的 GPU 无法获派任何硬件解码探测任务（包括通用的 DXVA11），导致最终生成的解码能力列表中仅保留两条默认的软件解码配置（H.264 1080p，`impl 37`）。

此外，在将探测结果持久化写入本地缓存文件前，程序设有一道校验逻辑：

```c
while (e->codec_impl == 37 || e->width * e->height == 0) { ... }
// 若校验发现仅包含软件解码方案，则输出日志 "decoder probe produced only software fallback"
// 随后终止缓存文件写入操作，留待下次启动时重新探测
```

由于探测结果未能包含任何有效的硬件加速方案，上述校验机制会拦截文件写入操作。这导致受影响设备的本地配置缓存文件始终无法生成，客户端在每次运行期间均被迫回退至软件解码模式。

受影响范围涵盖 Qualcomm Adreno 系列 GPU、Apple Silicon 系列集成 GPU、各类国产架构 GPU（如摩尔线程、景嘉微、寒武纪等），以及所有采用 ACPI 枚举（而非传统 PCI 总线枚举）的板载/集成显示设备。

除 NVIDIA、AMD 及 Intel 之外的**所有第三方架构 GPU** 均会触发此逻辑缺陷，导致硬件解码功能彻底失效（包括通用的 DXVA 接口亦无法调用）。

### 解决方式

#### 1. 探测函数补丁

移除探测函数中两处如果编号等于5就跳过的逻辑，使未知厂商的适配器能正常进入DXVA11探测流程。

```
41 83 f9 05   cmp r9d, 5      ->  41 83 f9 7f   cmp r9d, 0x7f
83 7b 20 05   cmp [rbx+0x20], 5 ->  83 7b 20 7f  cmp [rbx+0x20], 0x7f
```

> 注：在4.42及更早的版本中，旧方案会把厂商分类代码里未知厂商的默认返回值5改成2（Intel），字节上是
> `b8 05 00 00 00` -> `b8 02 00 00 00`，在4.46上会进入 Intel QSV / oneVPL 分支，导致UU远程卡死，因此新版本不再使用此方案。

#### 2. GPU探测器

UU只认可正常退出且带 `BATCH_DONE` 的输出，因此需要替换原版的`StreamerCodecDetector.exe`，强制返回 `BATCH_DONE`，并用此表补全。

```
H.264 4:2:0 8-bit  @4K     支持
H.265 4:2:0 8-bit  @4K     支持
H.265 4:2:0 10-bit @4K     支持
4:4:4（两种）、H.264 10-bit     不支持
```

脚本会逐项取原版探测值与上表的最高规格进行合并。

#### 3. 结果

UU 计算出 GPU 指纹、写出 `decoder_codec_capability_cache.json`，包含该 GPU 真实的硬解能力，例如：

```
H.264 4:2:0 8bit   3840x2160  DXVA11  x2
H.264 4:2:0 10bit  不支持      DXVA11  x2
H.264 4:4:4 8bit   不支持      DXVA11  x2
H.264 4:4:4 10bit  不支持      DXVA11  x2
H.265 4:2:0 8bit   3840x2160  DXVA11  x2
H.265 4:2:0 10bit  3840x2160  DXVA11  x2
H.265 4:4:4 8bit   不支持      DXVA11  x2
H.265 4:4:4 10bit  不支持      DXVA11  x2
```

UU随后会根据该文件调用GPU进行硬件解码，从而解锁超清和原画画质。

### 注意事项

- UU升级会覆盖回原版DLL，届时重新运行补丁即可（脚本会自动重新定位补丁点）。
- **解锁硬解不等于绝对没有问题。** 如果解锁后出现卡顿、花屏、掉帧，说明GPU可能不兼容。还原补丁并删除 `<UU>\config\streamer\decoder_codec_capability_cache.json` 来回滚到软解。
- 脚本在等待缓存期间可以随时按Ctrl+C停止，会尝试自动还原。如果UU进程仍然占用文件导致还原失败，完全退出UU后执行一次 `-Restore` 即可。

### 已确认可用的版本

| UU 远程                    | `streamer.dll` SHA256                                              | 补丁方案 | 补丁点                                                            | 验证机                    |
| -------------------------- | ------------------------------------------------------------------ | -------- | ----------------------------------------------------------------- | ------------------------- |
| GameViewer **4.46.0.4716** | `4600AD6F63C20A8EB3098DE2C9FE50A6300F39F882298C7FC3D7F3138DB1DD87` | 探测函数 | `0x933B47` `0x933C83`                                             | Qualcomm Adreno 8cx Gen 3 |
| GameViewer **4.42.0.2770** | `AB8ADE084C4F714FE5B21D1324B7E5D13E41BB036D4382E4BC231383B3D56E79` | 厂商分类 | `0x927A36` `0x927A73` `0x973E48` `0x9765C3` `0x9765F0` `0xB409CF` | Qualcomm Adreno 8cx Gen 3 |
| GameViewer **4.40.1.2090** | `2DB8630CB0D73B54135FF972AD82FC053FDEFF5117E67C5DD295EC4020C73276` | 厂商分类 | `0x9B172F`                                                        | Qualcomm Adreno 8cx Gen 3 |

不保证对后续版本的兼容性。补丁点靠字节特征重新定位，UU远程更换实现就会定位失败并直接中止。遇到这种情况烦请提交 Issue，或尝试自己适配。

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

## AIGC 声明

本项目中的部分代码由大语言模型（LLM）辅助完成。所有AI参与生成的内容均已通过开发者的人工审查、修改与测试。

## 许可与免责声明

- 本仓库以 **CC0 1.0 Universal** 发布，见 `LICENCE`。可自由使用、修改、再分发，无需署名。
- 本仓库与网易/UU远程官方无关，没有隶属关系，亦未获其授权或认可。
- 补丁会修改 `streamer.dll` 中厂商分类代码的几个立即数字节，仅出于互操作目的，便于在官方未支持的硬件上使用。UU远程及其组件的版权归网易公司所有，本仓库不包含任何UU远程的二进制文件。
- 本仓库仅供学习与研究。使用风险自负，请自行确保符合你所在地区的法律与软件许可条款。
