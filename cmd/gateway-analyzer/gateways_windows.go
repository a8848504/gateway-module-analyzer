package main

import (
	"errors"
	"strconv"
	"unsafe"

	"gateway-module-analyzer/internal/analyze"
	"golang.org/x/sys/windows"
)

const (
	listDeleteItem   = 0x1008
	listSetStyle     = 0x1036
	listInsertItem   = 0x104d
	listInsertColumn = 0x1061
	listSetItemText  = 0x1074
)

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

func (a *application) makeGatewayList() error {
	common := struct{ size, classes uint32 }{8, 1} // ICC_LISTVIEW_CLASSES
	comctl := windows.NewLazySystemDLL("comctl32.dll")
	initialized, _, _ := comctl.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&common)))
	if initialized == 0 {
		return errors.New("无法初始化网关列表组件")
	}
	a.list = a.control("SysListView32", "", 0x00018005, 0x0200, 0, 20, 126, 703, 307)
	if a.list == 0 {
		return errors.New("无法创建网关列表")
	}
	send.Call(a.list, listSetStyle, 0, 0x00010021) // Double buffer, full row selection, gridlines.
	columns := [...]struct {
		name          string
		width, format int
	}{
		{"网关", 385, 0},
		{"模组 1 数量", 145, 1},
		{"模组 2 数量", 145, 1},
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
		row := [3]string{label, strconv.FormatUint(gateway.Modules[0], 10), strconv.FormatUint(gateway.Modules[1], 10)}
		if index == len(a.rows) {
			item := listItem{mask: 1, item: int32(index), text: wide(row[0])}
			result, _, _ := send.Call(a.list, listInsertItem, 0, uintptr(unsafe.Pointer(&item)))
			if int32(result) < 0 {
				text(a.status, "无法添加网关列表行")
				return
			}
			a.rows = append(a.rows, [3]string{row[0]})
		}
		for column, value := range row {
			if value != a.rows[index][column] {
				item := listItem{subItem: int32(column), text: wide(value)}
				send.Call(a.list, listSetItemText, uintptr(index), uintptr(unsafe.Pointer(&item)))
			}
		}
		a.rows[index] = row
	}
	for index := len(a.rows) - 1; index >= len(gateways); index-- {
		send.Call(a.list, listDeleteItem, uintptr(index), 0)
	}
	a.rows = a.rows[:len(gateways)]
}
