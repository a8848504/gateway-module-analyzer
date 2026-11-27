# 网关模组分析

Windows 桌面工具。部署在接收网关数据的定位服务器上，按 TCP 端口旁路采样。程序读取定位服务已有连接上的入站数据，通过 TCP 重组、ETHE 校验和人员卡报文校验后，按网关、模组和通道统计。

## 现场使用

1. 从 [GitHub Releases](https://github.com/a8848504/gateway-module-analyzer/releases/latest) 下载对应的 EXE。普通 Intel 或 AMD 电脑选 `Windows-amd64`，Windows on ARM 选 `Windows-arm64`。运行时接受 Windows 管理员权限提示。
2. 输入定位服务正在接收的 TCP 端口，默认 `7115`。填写采样时间，默认 60 秒。
3. 默认选中 **结束后统计（Pktmon）**。该模式需要系统支持 `pktmon etl2pcap` 或兼容的 `pktmon pcapng` 命令。已安装 [Npcap](https://npcap.com/#download) 时也可选 **实时采样（Npcap）**，约每秒刷新一次。程序没有内置 Npcap 安装包。
4. 点击 **开始**。结果列表自动展示检测到的所有网关及两个模组的累计上报条数。可随时按 **停止** 结束采样并保留统计结果。

采样期间，原定位程序继续占用原 TCP 端口。启用旁路采样会产生少量抓包和解析开销。Pktmon 使用系统级会话，已有 Pktmon 会话或筛选规则时，程序会让管理员先检查其状态。

### 统计口径

- 人员卡 MAC 取末字节对 16 求余，直接得到通道号。通道 0–7 属于模组 1，通道 8–15 属于模组 2。
- 每条通过校验的人员卡上报计一次。支持 ETHE 内的 L、C、TA、TO、R 和 HJ 中已知的人员卡记录布局。批量帧逐记录计数。TCP 重传按序号去重，同一张卡的独立上报继续累计。
- 对于以太网网关，归属依据是报文中的网关 MAC。每行显示网关、模组 1 数量、模组 2 数量和结论。
- 差异率等于两个模组计数的差值除以较大的计数。超过 40% 显示红色「异常」，等于或低于 40% 显示绿色「正常」。两边均为 0 时按差异率 0% 处理。
- 单侧为零时，用分别归属模组 1 和模组 2 的已知正常卡，在同一网关覆盖范围内持续上报并复测。记录两侧计数和采样质量。报文汇总或多级转发时，结果归属报文标识中的网关。

## 在线更新

启动时会查询公开的 GitHub Releases，发现更高版本会在版本号旁显示红色提示。点击 **检查更新** 可以随时手动查询，无需登录或令牌。

检测到新正式版本后，确认即可下载与当前架构匹配的文件。进度条显示百分比和已下载大小，下载期间可以取消。连接中断或长时间没有收到数据时，程序会自动尝试备用的 GitHub 下载地址。程序校验发布资产的大小和 SHA-256，退出旧进程后替换 EXE 并重启。请将 EXE 放在有写权限的本地目录。

## 开发与发布

```sh
go test ./...
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -H windowsgui -X main.version=v1.0.0' -o dist/GatewayModuleAnalyzer-Windows-amd64.exe ./cmd/gateway-analyzer
```

命令行分析可用 `--raw path.bin` 读取已重组的 TCP 数据，或用 `--pcap path.pcapng --port 7115` 读取抓包文件。输出为 JSON。仓库里的 `gateway_capture.py` 可用于隔离环境的主动接入测试。现场定位服务器请用 EXE 的旁路模式。

推送形如 `v1.1.1` 的正式标签会触发 Windows 测试及两种架构的 Release 发布。发行文件名保持固定，版本以标签区分。
