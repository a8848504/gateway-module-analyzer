package main

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	startID        = 101
	stopID         = 102
	updateID       = 104
	cancelUpdateID = 105
	wmWork         = 0x8001
	wmCommand      = 0x0111
	wmNotify       = 0x004e
	wmStaticColor  = 0x0138
	wmClose        = 0x0010
	wmDestroy      = 0x0002
	cbAdd          = 0x0143
	cbGet          = 0x0147
	cbSet          = 0x014e
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
	window, instance, font                uintptr
	port, duration, mode, list, status    uintptr
	updateNotice                          uintptr
	progressBar, cancelUpdateButton       uintptr
	startButton, stopButton, updateButton uintptr
	scale                                 int
	busy, closing, stopping               bool
	checkingUpdate                        bool
	cancelDownload                        context.CancelFunc
	stop                                  chan struct{}
	rows                                  []gatewayRow
	rawFrameView                          gatewayRow
	mu                                    sync.Mutex
	work                                  []func()
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

func (a *application) makeUI() error {
	common := struct{ size, classes uint32 }{8, 0x21} // List-view and progress controls.
	comctl := windows.NewLazySystemDLL("comctl32.dll")
	initialized, _, _ := comctl.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&common)))
	if initialized == 0 {
		return errors.New("无法初始化窗口控件")
	}
	label := func(value string, x, y, w, h int) uintptr {
		return a.control("STATIC", value, 0, 0, 0, x, y, w, h)
	}
	const tabstop = 0x00010000
	const edge = 0x00000200
	const edit = 0x0080
	const combo = 0x00210003

	label("网关模组分析    "+version, 20, 16, 275, 24)
	a.updateNotice = label("", 310, 16, 245, 24)
	a.updateButton = a.control("BUTTON", "检查更新", tabstop, 0, updateID, 576, 10, 147, 31)
	label("TCP 端口", 20, 54, 76, 24)
	a.port = a.control("EDIT", "7115", tabstop|edit|0x2000, edge, 0, 96, 50, 72, 28)
	label("采样秒数", 188, 54, 76, 24)
	a.duration = a.control("EDIT", "60", tabstop|edit|0x2000, edge, 0, 264, 50, 70, 28)
	a.mode = a.control("COMBOBOX", "", combo, 0, 0, 354, 50, 171, 180)
	comboAdd(a.mode, "结束后统计（系统抓包）")
	comboAdd(a.mode, "实时采样（Npcap）")
	comboSet(a.mode, 0)
	a.startButton = a.control("BUTTON", "开始", tabstop|1, 0, startID, 547, 49, 82, 30)
	a.stopButton = a.control("BUTTON", "停止", tabstop, 0, stopID, 641, 49, 82, 30)
	a.status = label("请选择采样方式，定位服务可继续运行。", 20, 94, 703, 46)
	a.progressBar = a.control("msctls_progress32", "", 1, 0, 0, 20, 119, 580, 14)
	a.cancelUpdateButton = a.control("BUTTON", "取消下载", tabstop, 0, cancelUpdateID, 614, 105, 109, 29)
	if a.progressBar == 0 || a.cancelUpdateButton == 0 {
		return errors.New("无法创建更新进度控件")
	}
	a.showDownloadControls(false)

	a.setBusy(false)
	return a.makeGatewayList()
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
	enabled(a.updateButton, !value && !a.checkingUpdate)
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
	live := comboGet(a.mode) == 1
	stop := make(chan struct{})
	a.stop, a.stopping = stop, false
	a.setBusy(true)
	a.showGateways(nil)
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
				func(partial *capture.Sample) { a.post(func() { a.showGateways(partial.Report.Gateways) }) })
		} else {
			sample, err = capture.Run(uint16(port), duration, stop, status)
		}
		a.post(func() {
			a.stop, a.stopping = nil, false
			a.setBusy(false)
			if sample != nil {
				a.showGateways(sample.Report.Gateways)
			}
			if err != nil {
				text(a.status, "采样出现错误")
				messageBox(a.window, "采样出现错误", err.Error(), 0x30)
			} else {
				text(a.status, sampleStatus(sample))
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

func sampleStatus(sample *capture.Sample) string {
	report := sample.Report
	status := fmt.Sprintf("采样 %.0f 秒 · 目标端口 TCP 包 %d", sample.Duration.Seconds(), report.TCPPackets)
	if !report.FirstTCPPayload.IsZero() {
		span := report.LastTCPPayload.Sub(report.FirstTCPPayload)
		status += fmt.Sprintf(" · 目标端口载荷跨度 %.0f 秒", span.Seconds())
	}
	if len(report.Gateways) == 0 {
		status += " · 未识别到网关"
	}
	var issues []string
	if sample.Warning != "" {
		issues = append(issues, sample.Warning)
	}
	for _, issue := range []struct {
		label string
		count uint64
	}{
		{"TCP 缺口", report.TCPGaps}, {"抓包丢失", report.CaptureDropped}, {"截断", report.CaptureTruncated},
		{"加密上报未统计", report.EncryptedOuterFrames}, {"无法解析的网络包", report.UnsupportedPackets},
	} {
		if issue.count != 0 {
			issues = append(issues, fmt.Sprintf("%s %d", issue.label, issue.count))
		}
	}
	if report.BadOuterFrames != 0 {
		issues = append(issues, fmt.Sprintf("外帧错误 %d（帧尾 %d，校验和 %d）",
			report.BadOuterFrames, report.BadOuterTail, report.BadOuterChecksum))
	}
	var unknownBytes, badInnerFrames uint64
	for _, gateway := range report.Gateways {
		unknownBytes += gateway.UnknownBytes
		badInnerFrames += gateway.BadInnerFrames
	}
	if unknownBytes != 0 || badInnerFrames != 0 {
		issues = append(issues, fmt.Sprintf("未计入内帧 %d，未识别载荷 %d 字节", badInnerFrames, unknownBytes))
	}
	if len(issues) != 0 {
		return status + "\r\n可能不完整 · " + strings.Join(issues, " · ")
	}
	return status
}

func (a *application) showUpdateNotice(release *update.Release) {
	notice := ""
	if release != nil {
		notice = "发现新版本 " + release.Version
	}
	text(a.updateNotice, notice)
}

func (a *application) checkUpdate(interactive bool) {
	if a.checkingUpdate || (interactive && a.busy) {
		return
	}
	github := update.NewGitHub(releaseRepo)
	a.checkingUpdate = true
	if interactive {
		a.setBusy(true)
		text(a.status, "正在从 GitHub 检查更新…")
	} else {
		enabled(a.updateButton, false)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		release, err := github.Latest(ctx, version, runtime.GOARCH)
		a.post(func() {
			a.checkingUpdate = false
			if err == nil {
				a.showUpdateNotice(release)
			}
			if !interactive {
				enabled(a.updateButton, !a.busy)
				return
			}
			if err != nil {
				a.setBusy(false)
				text(a.status, "更新检查失败")
				detail := err.Error()
				if errors.Is(err, context.DeadlineExceeded) {
					detail = "连接 GitHub 检查版本超时，请稍后重试。"
				}
				messageBox(a.window, "更新检查失败", detail, 0x30)
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
			a.beginUpdateDownload(github, release)
		})
	}()
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
				app.checkUpdate(true)
			case cancelUpdateID:
				app.requestDownloadCancel()
			}
			return 0
		case wmNotify:
			// lParam points to a notification structure owned by Windows.
			header := (*notifyHeader)(*(*unsafe.Pointer)(unsafe.Pointer(&l)))
			if header != nil && header.source == app.list {
				switch header.code {
				case nmCustomDraw:
					return app.drawGatewayList((*listCustomDraw)(unsafe.Pointer(header)))
				case nmClick:
					app.clickGatewayList((*listClick)(unsafe.Pointer(header)))
					return 0
				}
			}
		case wmStaticColor:
			if l == app.updateNotice {
				gdi32.NewProc("SetTextColor").Call(w, abnormalColor)
				gdi32.NewProc("SetBkMode").Call(w, 1)                      // TRANSPARENT
				brush, _, _ := user32.NewProc("GetSysColorBrush").Call(15) // COLOR_BTNFACE
				return brush
			}
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
			if app.cancelDownload != nil {
				app.closing = true
				app.requestDownloadCancel()
				return 0
			}
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
		0x80000000, 0x80000000, app.px(764), app.px(497), 0, 0, instance, 0)
	if window == 0 {
		return err
	}
	app.window = window
	if err := app.makeUI(); err != nil {
		user32.NewProc("DestroyWindow").Call(window)
		return err
	}
	user32.NewProc("ShowWindow").Call(window, 1)
	app.checkUpdate(false)
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
