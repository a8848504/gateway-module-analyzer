package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"gateway-module-analyzer/internal/analyze"
	"gateway-module-analyzer/internal/update"
	"golang.org/x/sys/windows"
)

func TestGatewayListShowsAllGateways(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	host, _, err := create.Call(0, uintptr(unsafe.Pointer(wide("STATIC"))), 0, 0,
		0, 0, 760, 480, 0, 0, 0, 0)
	if host == 0 {
		t.Fatalf("create test host: %v", err)
	}
	defer user32.NewProc("DestroyWindow").Call(host)
	a := application{window: host, scale: 96}
	if err := a.makeUI(); err != nil {
		t.Fatal(err)
	}
	if comboGet(a.mode) != 0 {
		t.Fatal("Pktmon should be selected by default")
	}
	for i, want := range []string{"结束后统计（系统抓包）", "实时采样（Npcap）"} {
		var label [128]uint16
		send.Call(a.mode, 0x0148, uintptr(i), uintptr(unsafe.Pointer(&label[0]))) // CB_GETLBTEXT
		if got := windows.UTF16ToString(label[:]); got != want {
			t.Fatalf("sampling option %d = %q, want %q", i, got, want)
		}
	}
	header, _, _ := send.Call(a.list, 0x101f, 0, 0) // LVM_GETHEADER
	columns := []string{"网关", "类型", "模组 1 数量", "模组 2 数量", "结论", "首帧"}
	if count, _, _ := send.Call(header, 0x1200, 0, 0); int(count) != len(columns) {
		t.Fatalf("expected %d columns, got %d", len(columns), count)
	}
	for i, want := range columns {
		var buffer [32]uint16
		entry := listColumn{mask: 4, text: &buffer[0], textMax: int32(len(buffer))}
		send.Call(a.list, 0x105f, uintptr(i), uintptr(unsafe.Pointer(&entry))) // LVM_GETCOLUMNW
		if got := windows.UTF16ToString(buffer[:]); got != want {
			t.Fatalf("column %d = %q, want %q", i, got, want)
		}
	}
	assertRows := func(want ...gatewayCells) {
		t.Helper()
		if count, _, _ := send.Call(a.list, 0x1004, 0, 0); int(count) != len(want) {
			t.Fatalf("row count = %d, want %d", count, len(want))
		}
		for i, row := range want {
			for col, value := range row {
				var buffer [128]uint16
				cell := listItem{subItem: int32(col), text: &buffer[0], textMax: int32(len(buffer))}
				send.Call(a.list, 0x1073, uintptr(i), uintptr(unsafe.Pointer(&cell))) // LVM_GETITEMTEXTW
				if got := windows.UTF16ToString(buffer[:]); got != value {
					t.Fatalf("row %d col %d = %q, want %q", i, col, got, value)
				}
			}
		}
	}
	originalApp := app
	app = &a
	defer func() { app = originalApp }()
	a.showUpdateNotice(&update.Release{Version: "v9.0.0"})
	if got := read(a.updateNotice); got != "发现新版本 v9.0.0" {
		t.Fatalf("update notice = %q", got)
	}
	dc, _, err := gdi32.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		t.Fatalf("create test device context: %v", err)
	}
	defer gdi32.NewProc("DeleteDC").Call(dc)
	windowProc(a.window, wmStaticColor, dc, a.updateNotice)
	if color, _, _ := gdi32.NewProc("GetTextColor").Call(dc); color != abnormalColor {
		t.Fatalf("update notice color = %#x, want %#x", color, abnormalColor)
	}
	a.showUpdateNotice(nil)
	if got := read(a.updateNotice); got != "" {
		t.Fatalf("cleared update notice = %q", got)
	}
	a.showDownloadControls(true)
	a.showDownloadProgress(update.DownloadProgress{Received: 2 << 20, Total: 8 << 20, Attempt: 1})
	if pos, _, _ := send.Call(a.progressBar, 0x0408, 0, 0); pos != 25 { // PBM_GETPOS
		t.Fatalf("download progress position = %d, want 25", pos)
	}
	if label := read(a.status); !strings.Contains(label, "25%") || !strings.Contains(label, "2.00 / 8.00 MiB") {
		t.Fatalf("download progress label = %q", label)
	}
	a.showDownloadProgress(update.DownloadProgress{Total: 8 << 20, Attempt: 2})
	if label := read(a.status); !strings.Contains(label, "备用下载地址") {
		t.Fatalf("fallback stage label = %q", label)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.cancelDownload = cancel
	a.requestDownloadCancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("cancel download did not cancel its request")
	}
	a.showDownloadControls(false)
	assertColor := func(row uintptr, want uint32) {
		t.Helper()
		draw := &listCustomDraw{
			header: notifyHeader{source: a.list, code: nmCustomDraw},
			stage:  drawItemPrepaint | drawSubitem,
			item:   row, subItem: conclusionColumn,
		}
		var pinner runtime.Pinner
		pinner.Pin(draw)
		defer pinner.Unpin()
		result := windowProc(a.window, wmNotify, 0, uintptr(unsafe.Pointer(draw)))
		if result != drawNewColor || draw.textColor != want {
			t.Fatalf("row %d conclusion color = %#x, want %#x", row, draw.textColor, want)
		}
	}
	first := &analyze.Gateway{ID: "G1", MAC: "02:00:00:00:00:01", Address: "192.0.2.1:5000",
		DeviceTypes: []int{1, 6}, FirstFrame: "ETHE\x00\x00\x01\x01" + strings.Repeat("\x01", 12) + "\x0EM", Modules: [2]uint64{5, 0}}
	second := &analyze.Gateway{ID: "G2", DeviceTypes: []int{2},
		FirstFrame: "ETHE\x9c\x40\x02\x01" + strings.Repeat("\xCD", 40000) + strings.Repeat("\x02", 12) + "\x17M", Modules: [2]uint64{0, 8}}
	a.showGateways([]*analyze.Gateway{first, second})
	assertRows(gatewayCells{"02:00:00:00:00:01   192.0.2.1:5000", "0x01, 0x06", "5", "0", "异常", "查看"},
		gatewayCells{"G2", "0x02", "0", "8", "异常", "查看"})
	assertColor(0, abnormalColor)
	first.Modules = [2]uint64{100, 60}
	second.DeviceTypes = []int{2, 3}
	a.showGateways([]*analyze.Gateway{first, second})
	assertRows(gatewayCells{"02:00:00:00:00:01   192.0.2.1:5000", "0x01, 0x06", "100", "60", "正常", "查看"},
		gatewayCells{"G2", "0x02, 0x03", "0", "8", "异常", "查看"})
	assertColor(0, normalColor)
	second.MAC = "02:00:00:00:00:02"
	second.SIMHex = "0123456789AB"
	second.DeviceTypes = []int{0x0c}
	a.showGateways([]*analyze.Gateway{first, second})
	assertRows(gatewayCells{"02:00:00:00:00:01   192.0.2.1:5000", "0x01, 0x06", "100", "60", "正常", "查看"},
		gatewayCells{"02:00:00:00:00:02", "0x0C", "0", "8", "异常", "查看"})
	second.Address = "192.0.2.2:5000"
	a.showGateways([]*analyze.Gateway{second})
	assertRows(gatewayCells{"02:00:00:00:00:02   192.0.2.2:5000", "0x0C", "0", "8", "异常", "查看"})
	assertColor(0, abnormalColor)
	assertRawFrameDialog(t, &a, second.FirstFrame)
	a.showGateways(nil)
	assertRows()
}

func assertRawFrameDialog(t *testing.T, a *application, frame string) {
	t.Helper()
	bounds := [4]int32{0, rawFrameColumn}
	if found, _, _ := send.Call(a.list, 0x1038, 0, uintptr(unsafe.Pointer(&bounds[0]))); found == 0 { // LVM_GETSUBITEMRECT
		t.Fatal("first row has no raw-frame cell")
	}
	click := listClick{header: notifyHeader{source: a.list, code: nmClick},
		position: [2]int32{(bounds[0] + bounds[2]) / 2, (bounds[1] + bounds[3]) / 2}}
	var pin runtime.Pinner
	pin.Pin(&click)
	defer pin.Unpin()
	windowProc(a.window, wmNotify, 0, uintptr(unsafe.Pointer(&click)))
	if len(a.work) != 1 {
		t.Fatal("clicking the first-frame cell did not queue a dialog")
	}
	var opened bool
	timerProc := windows.NewCallback(func(_ uintptr, _ uint32, _ uintptr, _ uint32) uintptr {
		dialog, _, _ := user32.NewProc("FindWindowW").Call(0, uintptr(unsafe.Pointer(wide(rawDialogTitle))))
		if dialog == 0 {
			return 0
		}
		opened = true
		edit, _, _ := user32.NewProc("GetDlgItem").Call(dialog, rawFrameEdit)
		length, _, _ := user32.NewProc("GetWindowTextLengthW").Call(edit)
		if want := len(rawFrameHex(frame)); int(length) != want {
			t.Errorf("raw-frame display length = %d, want %d", length, want)
		}
		if got := read(edit); !strings.HasPrefix(got, "45 54 48 45 9C 40 02 01 CD CD") {
			t.Errorf("raw-frame dialog opened unexpected bytes: %.80s", got)
		}
		user32.NewProc("PostMessageW").Call(dialog, wmClose, 0, 0)
		return 0
	})
	timer, _, err := user32.NewProc("SetTimer").Call(a.window, 1, 30, timerProc)
	if timer == 0 {
		t.Fatalf("cannot schedule raw-frame dialog check: %v", err)
	}
	defer user32.NewProc("KillTimer").Call(a.window, timer)
	windowProc(a.window, wmWork, 0, 0)
	if !opened {
		t.Fatal("raw-frame dialog did not open")
	}
}

func TestModuleConclusionThreshold(t *testing.T) {
	for _, test := range []struct {
		first, second uint64
		want          string
	}{
		{0, 0, "正常"},
		{17, 17, "正常"},
		{0, 1, "异常"},
		{100, 61, "正常"},
		{100, 60, "正常"},
		{100, 59, "异常"},
		{59, 100, "异常"},
		{3, 2, "正常"},
		{3, 1, "异常"},
		{^uint64(0), 11068046444225730969, "正常"},
		{^uint64(0), 11068046444225730968, "异常"},
	} {
		if got := moduleConclusion(test.first, test.second); got != test.want {
			t.Errorf("moduleConclusion(%d, %d) = %s, want %s", test.first, test.second, got, test.want)
		}
	}
}
