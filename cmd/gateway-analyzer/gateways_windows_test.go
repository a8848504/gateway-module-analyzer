package main

import (
	"runtime"
	"testing"
	"unsafe"

	"gateway-module-analyzer/internal/analyze"
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
	if err := a.makeGatewayList(); err != nil {
		t.Fatal(err)
	}
	header, _, _ := send.Call(a.list, 0x101f, 0, 0) // LVM_GETHEADER
	if count, _, _ := send.Call(header, 0x1200, 0, 0); count != 3 {
		t.Fatalf("expected three columns, got %d", count)
	}
	assertRows := func(want ...[3]string) {
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
	first := &analyze.Gateway{ID: "G1", MAC: "02:00:00:00:00:01", Address: "192.0.2.1:5000", Modules: [2]uint64{5, 0}}
	second := &analyze.Gateway{ID: "G2", Modules: [2]uint64{0, 8}}
	a.showGateways([]*analyze.Gateway{first, second})
	assertRows([3]string{"02:00:00:00:00:01   192.0.2.1:5000", "5", "0"}, [3]string{"G2", "0", "8"})
	first.Modules = [2]uint64{7, 4}
	a.showGateways([]*analyze.Gateway{first, second})
	assertRows([3]string{"02:00:00:00:00:01   192.0.2.1:5000", "7", "4"}, [3]string{"G2", "0", "8"})
	a.showGateways(nil)
	assertRows()
}
