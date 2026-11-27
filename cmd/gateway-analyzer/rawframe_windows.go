package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rawDialogTitle = "首条原始报文"
	rawFrameEdit   = 201
	rawFrameCopy   = 202
	dialogCancel   = 2
)

var rawDialogCallback = windows.NewCallback(rawDialogProc)

// DLGTEMPLATE followed by the empty menu, class and title fields.
type rawDialogTemplate struct {
	style, exStyle      uint32
	controls            uint16
	x, y, width, height int16
	menu, class, title  uint16
}

func (a *application) showRawFrame(row gatewayRow) {
	if a.closing || a.rawFrameView.firstFrame != "" {
		return
	}
	a.rawFrameView = row
	defer func() { a.rawFrameView = gatewayRow{} }()
	template := rawDialogTemplate{
		style: 0x80c80880, // Popup with a caption, system menu, centered modal frame.
		width: 352, height: 220,
	}
	result, _, _ := user32.NewProc("DialogBoxIndirectParamW").Call(a.instance,
		uintptr(unsafe.Pointer(&template)), a.window, rawDialogCallback, 0)
	if result != 1 {
		messageBox(a.window, rawDialogTitle, "无法打开原始报文窗口。", 0x30)
	}
}

func rawDialogProc(window uintptr, event uint32, w, _ uintptr) uintptr {
	switch event {
	case 0x0110: // WM_INITDIALOG.
		text(window, rawDialogTitle)
		var client [4]int32
		user32.NewProc("GetClientRect").Call(window, uintptr(unsafe.Pointer(&client[0])))
		width, height := int(client[2])*96/app.scale, int(client[3])*96/app.scale
		controls := application{window: window, instance: app.instance, font: app.font, scale: app.scale}
		row := app.rawFrameView
		frame := row.firstFrame
		const tabStop = 0x00010000
		label := fmt.Sprintf("网关 %s   ·   类型 0x%02X   ·   %d 字节", row.cells[0], frame[6], len(frame))
		controls.control("STATIC", label, 0, 0, 0, 12, 12, width-24, 22)
		// WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY.
		edit := controls.control("EDIT", "", tabStop|0x00200844, 0x200, rawFrameEdit, 12, 39, width-24, height-89)
		copyButton := controls.control("BUTTON", "复制十六进制", tabStop, 0, rawFrameCopy, width-206, height-38, 113, 26)
		closeButton := controls.control("BUTTON", "关闭", tabStop|1, 0, dialogCancel, width-85, height-38, 73, 26)
		if edit == 0 || copyButton == 0 || closeButton == 0 {
			user32.NewProc("EndDialog").Call(window, 0)
			return 1
		}
		fixedFont, _, _ := gdi32.NewProc("GetStockObject").Call(11) // ANSI_FIXED_FONT.
		send.Call(edit, 0x0030, fixedFont, 1)                       // WM_SETFONT.
		value := rawFrameHex(frame)
		send.Call(edit, 0x00c5, uintptr(len(value)+1), 0) // EM_SETLIMITTEXT.
		text(edit, value)
		user32.NewProc("SetFocus").Call(edit)
		return 0
	case wmCommand:
		switch uint16(w) {
		case rawFrameCopy:
			edit, _, _ := user32.NewProc("GetDlgItem").Call(window, rawFrameEdit)
			var start, end uint32
			send.Call(edit, 0x00b0, uintptr(unsafe.Pointer(&start)), uintptr(unsafe.Pointer(&end))) // EM_GETSEL.
			send.Call(edit, 0x00b1, 0, ^uintptr(0))                                                 // EM_SETSEL.
			send.Call(edit, 0x0301, 0, 0)                                                           // WM_COPY.
			send.Call(edit, 0x00b1, uintptr(start), uintptr(end))                                   // EM_SETSEL.
			return 1
		case dialogCancel:
			user32.NewProc("EndDialog").Call(window, 1)
			return 1
		}
	case wmClose:
		user32.NewProc("EndDialog").Call(window, 1)
		return 1
	}
	return 0
}

func rawFrameHex(frame string) string {
	const digits = "0123456789ABCDEF"
	const lineBytes = 24
	var result strings.Builder
	result.Grow(len(frame)*3 + len(frame)/lineBytes)
	for i := 0; i < len(frame); i++ {
		if i > 0 {
			if i%lineBytes == 0 {
				result.WriteString("\r\n")
			} else {
				result.WriteByte(' ')
			}
		}
		result.WriteByte(digits[frame[i]>>4])
		result.WriteByte(digits[frame[i]&0x0f])
	}
	return result.String()
}
