package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"gateway-module-analyzer/internal/capture"
	"gateway-module-analyzer/internal/update"
	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")
	shell  = windows.NewLazySystemDLL("shell32.dll")
	create = user32.NewProc("CreateWindowExW")
	send   = user32.NewProc("SendMessageW")
	set    = user32.NewProc("SetWindowTextW")
	app    *application
)

const (
	startID   = 101
	stopID    = 102
	gatewayID = 103
	updateID  = 104
	wmWork    = 0x8001
	wmCommand = 0x0111
	wmClose   = 0x0010
	wmDestroy = 0x0002
	cbAdd     = 0x0143
	cbReset   = 0x014b
	cbGet     = 0x0147
	cbSet     = 0x014e
)

type windowClass struct {
	size, style                        uint32
	procedure                          uintptr
	classExtra, windowExtra            int32
	instance, icon, cursor, background uintptr
	menuName, className                *uint16
	smallIcon                          uintptr
}

type message struct {
	window         uintptr
	message        uint32
	wParam, lParam uintptr
	time           uint32
	x, y           int32
	private        uint32
}

type application struct {
	window, instance, font                     uintptr
	port, duration, mode, gateway, token       uintptr
	startButton, stopButton, updateButton      uintptr
	status, first, second, detail, diagnostics uintptr
	scale                                      int
	busy, closing, stopping                    bool
	stop                                       chan struct{}
	sample                                     *capture.Sample
	gatewayIDs                                 []string
	mu                                         sync.Mutex
	work                                       []func()
}

func wide(value string) *uint16 {
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(value, "\x00", ""))
	return p
}

func messageBox(window uintptr, title, body string, flags uintptr) uintptr {
	result, _, _ := user32.NewProc("MessageBoxW").Call(window, uintptr(unsafe.Pointer(wide(body))),
		uintptr(unsafe.Pointer(wide(title))), flags)
	return result
}

func text(control uintptr, value string) {
	set.Call(control, uintptr(unsafe.Pointer(wide(value))))
}

func read(control uintptr) string {
	var buf [1024]uint16
	user32.NewProc("GetWindowTextW").Call(control, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:])
}

func enabled(control uintptr, value bool) {
	state := uintptr(0)
	if value {
		state = 1
	}
	user32.NewProc("EnableWindow").Call(control, state)
}

func comboAdd(control uintptr, value string) {
	send.Call(control, cbAdd, 0, uintptr(unsafe.Pointer(wide(value))))
}

func comboGet(control uintptr) int {
	result, _, _ := send.Call(control, cbGet, 0, 0)
	return int(result)
}

func comboSet(control uintptr, index int) { send.Call(control, cbSet, uintptr(index), 0) }

func (a *application) px(value int) uintptr { return uintptr(value * a.scale / 96) }

func (a *application) control(class, value string, style, exStyle uintptr, id, x, y, w, h int) uintptr {
	handle, _, _ := create.Call(exStyle, uintptr(unsafe.Pointer(wide(class))), uintptr(unsafe.Pointer(wide(value))),
		style|0x50000000, a.px(x), a.px(y), a.px(w), a.px(h), a.window, uintptr(id), a.instance, 0)
	send.Call(handle, 0x0030, a.font, 1) // WM_SETFONT
	return handle
}

func (a *application) makeUI() {
	label := func(value string, x, y, w, h int) uintptr {
		return a.control("STATIC", value, 0, 0, 0, x, y, w, h)
	}
	const tabstop = 0x00010000
	const edge = 0x00000200
	const edit = 0x0080
	const combo = 0x00210003

	label("网关模组分析    "+version, 20, 16, 665, 24)
	label("TCP 端口", 20, 54, 76, 24)
	a.port = a.control("EDIT", "7115", tabstop|edit|0x2000, edge, 0, 96, 50, 72, 28)
	label("采样秒数", 188, 54, 76, 24)
	a.duration = a.control("EDIT", "60", tabstop|edit|0x2000, edge, 0, 264, 50, 70, 28)
	a.mode = a.control("COMBOBOX", "", combo, 0, 0, 354, 50, 171, 180)
	comboAdd(a.mode, "实时采样（Npcap）")
	comboAdd(a.mode, "结束后统计（Pktmon）")
	comboSet(a.mode, 0)
	a.startButton = a.control("BUTTON", "开始", tabstop|1, 0, startID, 547, 49, 82, 30)
	a.stopButton = a.control("BUTTON", "停止", tabstop, 0, stopID, 641, 49, 82, 30)
	a.status = label("请选择采样方式，定位服务可继续运行。", 20, 94, 703, 23)

	label("网关", 20, 129, 48, 22)
	a.gateway = a.control("COMBOBOX", "", combo, 0, gatewayID, 68, 124, 655, 205)
	a.detail = label("等待网关数据", 20, 163, 703, 26)
	label("模组 1 · 通道 0–7", 20, 199, 336, 24)
	label("模组 2 · 通道 8–15", 380, 199, 343, 24)
	const readOnly = 0x0804
	a.first = a.control("EDIT", "", readOnly, edge, 0, 20, 222, 339, 204)
	a.second = a.control("EDIT", "", readOnly, edge, 0, 380, 222, 343, 204)
	a.diagnostics = label("", 20, 440, 703, 65)

	label("GitHub 只读令牌", 20, 521, 120, 23)
	a.token = a.control("EDIT", os.Getenv("GATEWAY_ANALYZER_GITHUB_TOKEN"),
		tabstop|edit|0x0020, edge, 0, 142, 516, 418, 29)
	a.updateButton = a.control("BUTTON", "检查更新", tabstop, 0, updateID, 576, 515, 147, 31)
	a.setBusy(false)
}

func (a *application) post(fn func()) {
	a.mu.Lock()
	a.work = append(a.work, fn)
	a.mu.Unlock()
	user32.NewProc("PostMessageW").Call(a.window, wmWork, 0, 0)
}

func (a *application) setBusy(value bool) {
	a.busy = value
	enabled(a.startButton, !value)
	enabled(a.stopButton, a.stop != nil && !a.stopping)
	enabled(a.port, !value)
	enabled(a.duration, !value)
	enabled(a.mode, !value)
	enabled(a.token, !value)
	enabled(a.updateButton, !value)
}

func (a *application) beginCapture() {
	if a.busy {
		return
	}
	port, errPort := strconv.ParseUint(strings.TrimSpace(read(a.port)), 10, 16)
	seconds, errDuration := strconv.Atoi(strings.TrimSpace(read(a.duration)))
	if errPort != nil || port == 0 || errDuration != nil || seconds < 5 || seconds > 1800 {
		messageBox(a.window, "输入无效", "请输入 1–65535 的 TCP 端口及 5–1800 秒的采样时间。", 0x30)
		return
	}
	live := comboGet(a.mode) == 0
	stop := make(chan struct{})
	a.stop, a.stopping = stop, false
	a.setBusy(true)
	a.sample = nil
	a.gatewayIDs = nil
	send.Call(a.gateway, cbReset, 0, 0)
	a.showGateway()
	text(a.status, "正在打开旁路抓包…")
	go func() {
		duration := time.Duration(seconds) * time.Second
		status := func(value string) {
			a.post(func() {
				if !a.stopping {
					text(a.status, value)
				}
			})
		}
		var sample *capture.Sample
		var err error
		if live {
			sample, err = capture.RunLive(uint16(port), duration, stop, status,
				func(partial *capture.Sample) { a.post(func() { a.showSample(partial) }) })
		} else {
			sample, err = capture.Run(uint16(port), duration, stop, status)
		}
		a.post(func() {
			a.stop, a.stopping = nil, false
			a.setBusy(false)
			if sample != nil {
				a.showSample(sample)
			}
			if err != nil {
				text(a.status, "采样出现错误")
				messageBox(a.window, "采样出现错误", err.Error(), 0x30)
			} else {
				text(a.status, "采样结束")
			}
			if a.closing {
				user32.NewProc("DestroyWindow").Call(a.window)
			}
		})
	}()
}

func (a *application) stopCapture() {
	if a.stop != nil && !a.stopping {
		close(a.stop)
		a.stopping = true
		enabled(a.stopButton, false)
		text(a.status, "正在结束采样并整理结果…")
	}
}

func (a *application) showSample(sample *capture.Sample) {
	previous := comboGet(a.gateway)
	var selected string
	if previous >= 0 && previous < len(a.gatewayIDs) {
		selected = a.gatewayIDs[previous]
	}
	a.sample = sample
	gateways := sample.Report.Gateways
	same := len(a.gatewayIDs) == len(gateways)
	for i, gateway := range gateways {
		same = same && a.gatewayIDs[i] == gateway.ID
	}
	if !same {
		send.Call(a.gateway, cbReset, 0, 0)
		a.gatewayIDs = a.gatewayIDs[:0]
		index, most := -1, uint64(0)
		for i, gateway := range gateways {
			a.gatewayIDs = append(a.gatewayIDs, gateway.ID)
			label := gateway.ID
			if gateway.MAC != "" {
				label = gateway.MAC + "   " + gateway.Address
			}
			comboAdd(a.gateway, label)
			total := gateway.Modules[0] + gateway.Modules[1]
			if gateway.ID == selected {
				index = i
			}
			if selected == "" && (index < 0 || total > most) {
				index, most = i, total
			}
		}
		if index >= 0 {
			comboSet(a.gateway, index)
		}
	}
	a.showGateway()
}

func (a *application) showGateway() {
	if a.sample == nil {
		text(a.detail, "等待网关数据")
		text(a.first, "")
		text(a.second, "")
		text(a.diagnostics, "")
		return
	}
	report := a.sample.Report
	quality := fmt.Sprintf("采样 %.1f 秒 · TCP 包 %d · 有效 ETHE 帧 %d · TCP 缺口 %d · 抓包丢失/截断 %d/%d",
		a.sample.Duration.Seconds(), report.TCPPackets, report.OuterFrames, report.TCPGaps,
		report.CaptureDropped, report.CaptureTruncated)
	quality += fmt.Sprintf("\r\n外帧校验异常 %d · 边界半帧 %d · 不支持的网络包 %d",
		report.BadOuterFrames, report.PartialOuterFrames, report.UnsupportedPackets)
	if a.sample.PossibleFileCap {
		quality += " · 日志可能已覆盖"
	}
	if a.sample.Warning != "" {
		quality += "\r\n" + a.sample.Warning
	}
	text(a.diagnostics, quality)

	index := comboGet(a.gateway)
	if index < 0 || index >= len(report.Gateways) {
		text(a.detail, "本次采样尚无可识别的网关")
		text(a.first, "")
		text(a.second, "")
		return
	}
	gateway := report.Gateways[index]
	one, two := gateway.Modules[0], gateway.Modules[1]
	state := "两个模组均观察到上报"
	if one == 0 && two == 0 {
		state = "尚未观察到人员卡上报"
	} else if one == 0 || two == 0 {
		state = "当前只观察到单侧上报"
		if a.stop == nil {
			state = "单侧为零，请用两组已知卡复测"
		}
	}
	if report.TCPGaps != 0 || report.CaptureDropped != 0 || report.CaptureTruncated != 0 ||
		report.UnsupportedPackets != 0 || report.BadOuterFrames != 0 || gateway.BadInnerFrames != 0 || gateway.UnknownBytes != 0 ||
		a.sample.PossibleFileCap || a.sample.Warning != "" {
		state += " · 采样可能不完整"
	}
	text(a.detail, fmt.Sprintf("卡号去重 %d · 上报 %d · %s", gateway.UniqueCards, one+two, state))
	text(a.diagnostics, quality+fmt.Sprintf(" · 所选网关内帧异常 %d、未识别 %d 字节",
		gateway.BadInnerFrames, gateway.UnknownBytes))
	for module, control := range []uintptr{a.first, a.second} {
		var lines strings.Builder
		fmt.Fprintf(&lines, "合计上报    %d\r\n\r\n", gateway.Modules[module])
		for channel := module * 8; channel < module*8+8; channel++ {
			fmt.Fprintf(&lines, "通道 %02d       %d\r\n", channel, gateway.Channels[channel])
		}
		text(control, lines.String())
	}
}

func (a *application) checkUpdate() {
	if a.busy {
		return
	}
	github := update.NewGitHub(releaseRepo, read(a.token))
	a.setBusy(true)
	text(a.status, "正在从 GitHub 检查更新…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		release, err := github.Latest(ctx, version, runtime.GOARCH)
		a.post(func() {
			if err != nil {
				a.setBusy(false)
				text(a.status, "更新检查失败")
				messageBox(a.window, "更新检查失败", err.Error(), 0x30)
				return
			}
			if release == nil {
				a.setBusy(false)
				text(a.status, "当前已是最新版本")
				return
			}
			if messageBox(a.window, "发现新版本", "GitHub 已发布 "+release.Version+"。下载、校验并重启本程序？", 0x124) != 6 {
				a.setBusy(false)
				text(a.status, "已取消更新")
				return
			}
			text(a.status, "正在下载并校验更新…")
			go a.installUpdate(github, release)
		})
	}()
}

func (a *application) installUpdate(github *update.GitHub, release *update.Release) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target, err := os.Executable()
	var candidate string
	if err == nil {
		candidate, err = github.Download(ctx, release, filepath.Dir(target))
	}
	if err == nil {
		err = update.StartReplacement(target, candidate, release.Digest)
	}
	a.post(func() {
		if err != nil {
			if candidate != "" {
				os.Remove(candidate)
			}
			a.setBusy(false)
			text(a.status, "更新失败")
			messageBox(a.window, "更新失败", err.Error(), 0x30)
			return
		}
		user32.NewProc("DestroyWindow").Call(a.window)
	})
}

func windowProc(window uintptr, event uint32, w, l uintptr) uintptr {
	if app != nil {
		switch event {
		case wmCommand:
			switch uint16(w) {
			case startID:
				app.beginCapture()
			case stopID:
				app.stopCapture()
			case updateID:
				app.checkUpdate()
			case gatewayID:
				if uint16(w>>16) == 1 {
					app.showGateway()
				}
			}
			return 0
		case wmWork:
			app.mu.Lock()
			work := app.work
			app.work = nil
			app.mu.Unlock()
			for _, fn := range work {
				fn()
			}
			return 0
		case wmClose:
			if app.stop != nil {
				app.closing = true
				app.stopCapture()
				return 0
			}
			if app.busy {
				return 0
			}
		case wmDestroy:
			user32.NewProc("PostQuitMessage").Call(0)
			return 0
		}
	}
	result, _, _ := user32.NewProc("DefWindowProcW").Call(window, uintptr(event), w, l)
	return result
}

func gui() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	admin, _, _ := shell.NewProc("IsUserAnAdmin").Call()
	if admin == 0 {
		target, err := os.Executable()
		if err != nil {
			return err
		}
		result, _, _ := shell.NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(wide("runas"))),
			uintptr(unsafe.Pointer(wide(target))), 0, 0, 1)
		if result <= 32 {
			return fmt.Errorf("旁路采样需要管理员权限，Windows 启动返回 %d", result)
		}
		return nil
	}
	user32.NewProc("SetProcessDPIAware").Call()
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	instance, _, _ := kernel.NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512)
	font, _, _ := gdi32.NewProc("GetStockObject").Call(17)
	dpi := uintptr(96)
	if proc := user32.NewProc("GetDpiForSystem"); proc.Find() == nil {
		if value, _, _ := proc.Call(); value != 0 {
			dpi = value
		}
	}
	app = &application{instance: instance, font: font, scale: int(dpi)}
	class := windowClass{procedure: windows.NewCallback(windowProc), instance: instance,
		cursor: cursor, background: 16, className: wide("GatewayModuleAnalyzer")}
	class.size = uint32(unsafe.Sizeof(class))
	if result, _, err := user32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class))); result == 0 {
		return err
	}
	window, _, err := create.Call(0, uintptr(unsafe.Pointer(class.className)),
		uintptr(unsafe.Pointer(wide("网关模组分析"))), 0x00ca0000,
		0x80000000, 0x80000000, app.px(764), app.px(601), 0, 0, instance, 0)
	if window == 0 {
		return err
	}
	app.window = window
	app.makeUI()
	user32.NewProc("ShowWindow").Call(window, 1)
	var msg message
	for {
		result, _, err := user32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) < 0 {
			return err
		}
		if result == 0 {
			return nil
		}
		if handled, _, _ := user32.NewProc("IsDialogMessageW").Call(window, uintptr(unsafe.Pointer(&msg))); handled == 0 {
			user32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
			user32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
}

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "--apply-update":
		err = update.Apply(os.Args[2:])
		if err != nil {
			messageBox(0, "安装更新失败", err.Error(), 0x30)
			os.Exit(1)
		}
		return
	case len(os.Args) == 3 && os.Args[1] == "--cleanup-helper":
		go update.CleanHelper(os.Args[2])
		err = gui()
	case len(os.Args) > 1:
		if err := cli(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	default:
		err = gui()
	}
	if err != nil {
		messageBox(0, "网关模组分析", err.Error(), 0x30)
		os.Exit(1)
	}
}
