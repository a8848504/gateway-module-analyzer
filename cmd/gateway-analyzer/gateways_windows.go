package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"gateway-module-analyzer/internal/analyze"
)

const (
	listDeleteItem   = 0x1008
	listSetStyle     = 0x1036
	listSubitemHit   = 0x1039
	listInsertItem   = 0x104d
	listInsertColumn = 0x1061
	listSetItemText  = 0x1074

	conclusionColumn   = 4
	rawFrameColumn     = 5
	normalConclusion   = "正常"
	abnormalConclusion = "异常"
	normalColor        = 0x00346516 // COLORREF for #166534
	abnormalColor      = 0x001823b4 // COLORREF for #B42318

	nmCustomDraw       = ^uint32(11) // NM_CUSTOMDRAW is -12.
	nmClick            = ^uint32(1)  // NM_CLICK is -2.
	drawPrepaint       = 0x000001
	drawItemPrepaint   = 0x010001
	drawSubitem        = 0x020000
	drawNotifySubitems = 0x20 // Also CDRF_NOTIFYITEMDRAW at control prepaint.
	drawNewColor       = 0x02 // CDRF_NEWFONT tells the control to use the changed color.
)

type gatewayCells [rawFrameColumn + 1]string

type gatewayRow struct {
	cells      gatewayCells
	firstFrame string
}

type listColumn struct {
	mask          uint32
	format, width int32
	text          *uint16
	textMax, subItem, image, order, minWidth, defaultWidth,
	idealWidth int32
}

type listItem struct {
	mask                         uint32
	item, subItem                int32
	state, stateMask             uint32
	text                         *uint16
	textMax, image               int32
	param                        uintptr
	indent, groupID              int32
	columns                      uint32
	columnIndices, columnFormats uintptr
	group                        int32
}

type notifyHeader struct {
	source, id uintptr
	code       uint32
}

// Prefix of NMITEMACTIVATE, through the click position.
type listClick struct {
	header                      notifyHeader
	item, subItem               int32
	newState, oldState, changed uint32
	position                    [2]int32
}

type listHit struct {
	position             [2]int32
	flags                uint32
	item, subItem, group int32
}

// Prefix of NMLVCUSTOMDRAW, through the fields used for text color.
type listCustomDraw struct {
	header                     notifyHeader
	stage                      uint32
	deviceContext              uintptr
	bounds                     [4]int32
	item                       uintptr
	itemState                  uint32
	itemParam                  uintptr
	textColor, backgroundColor uint32
	subItem                    int32
}

func (a *application) drawGatewayList(draw *listCustomDraw) uintptr {
	switch draw.stage {
	case drawPrepaint, drawItemPrepaint:
		return drawNotifySubitems
	case drawItemPrepaint | drawSubitem:
		if draw.subItem == conclusionColumn && draw.item < uintptr(len(a.rows)) {
			draw.textColor = normalColor
			if a.rows[draw.item].cells[conclusionColumn] == abnormalConclusion {
				draw.textColor = abnormalColor
			}
			return drawNewColor
		}
	}
	return 0
}

func (a *application) clickGatewayList(click *listClick) {
	hit := listHit{position: click.position}
	row, _, _ := send.Call(a.list, listSubitemHit, 0, uintptr(unsafe.Pointer(&hit)))
	if row < uintptr(len(a.rows)) && hit.subItem == rawFrameColumn && a.rows[row].firstFrame != "" {
		selected := a.rows[row]
		a.post(func() { a.showRawFrame(selected) })
	}
}

func moduleConclusion(first, second uint64) string {
	larger, smaller := max(first, second), min(first, second)
	// 40% is 2/5. Evaluate the integer limit without rounding or overflow.
	limit := (larger/5)*2 + ((larger%5)*2)/5
	if larger-smaller > limit {
		return abnormalConclusion
	}
	return normalConclusion
}

func (a *application) makeGatewayList() error {
	a.list = a.control("SysListView32", "", 0x00018005, 0x0200, 0, 20, 147, 703, 286)
	if a.list == 0 {
		return errors.New("无法创建网关列表")
	}
	send.Call(a.list, listSetStyle, 0, 0x00010021) // Double buffer, full row selection, gridlines.
	columns := [...]struct {
		name          string
		width, format int
	}{
		{"网关", 260, 0},
		{"类型", 108, 0},
		{"模组 1 数量", 88, 1},
		{"模组 2 数量", 88, 1},
		{"结论", 65, 2},
		{"首帧", 68, 2},
	}
	for index, column := range columns {
		entry := listColumn{mask: 7, format: int32(column.format), width: int32(a.px(column.width)), text: wide(column.name)}
		result, _, _ := send.Call(a.list, listInsertColumn, uintptr(index), uintptr(unsafe.Pointer(&entry)))
		if int32(result) < 0 {
			return errors.New("无法创建网关列表列")
		}
	}
	return nil
}

func (a *application) showGateways(gateways []*analyze.Gateway) {
	for index, gateway := range gateways {
		label := gateway.ID
		if gateway.MAC != "" {
			label = gateway.MAC
			if gateway.Address != "" {
				label += "   " + gateway.Address
			}
		}
		types := make([]string, len(gateway.DeviceTypes))
		for i, deviceType := range gateway.DeviceTypes {
			types[i] = fmt.Sprintf("0x%02X", deviceType)
		}
		first, second := gateway.Modules[0], gateway.Modules[1]
		row := gatewayRow{cells: gatewayCells{label, strings.Join(types, ", "), strconv.FormatUint(first, 10),
			strconv.FormatUint(second, 10), moduleConclusion(first, second)}, firstFrame: gateway.FirstFrame}
		if row.firstFrame != "" {
			row.cells[rawFrameColumn] = "查看"
		}
		var previous gatewayCells
		if index == len(a.rows) {
			item := listItem{mask: 1, item: int32(index), text: wide(row.cells[0])}
			a.rows = append(a.rows, row)
			result, _, _ := send.Call(a.list, listInsertItem, 0, uintptr(unsafe.Pointer(&item)))
			if int32(result) < 0 {
				a.rows = a.rows[:index]
				text(a.status, "无法添加网关列表行")
				return
			}
			previous[0] = row.cells[0]
		} else {
			previous = a.rows[index].cells
			a.rows[index] = row
		}
		for column, value := range row.cells {
			if value != previous[column] {
				item := listItem{subItem: int32(column), text: wide(value)}
				send.Call(a.list, listSetItemText, uintptr(index), uintptr(unsafe.Pointer(&item)))
			}
		}
	}
	for index := len(a.rows) - 1; index >= len(gateways); index-- {
		send.Call(a.list, listDeleteItem, uintptr(index), 0)
	}
	clear(a.rows[len(gateways):])
	a.rows = a.rows[:len(gateways)]
}
