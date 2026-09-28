//go:build windows

package systemproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Use WinINet's per-connection API, including PAC/auto-detect flags, rather
// than only editing ProxyEnable in the registry and leaving PAC active.
var wininet = windows.NewLazySystemDLL("wininet.dll")
var queryOption = wininet.NewProc("InternetQueryOptionW")
var setOption = wininet.NewProc("InternetSetOptionW")
var globalFree = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")

type winOption struct {
	Option uint32
	Value  uint64
}
type winOptions struct {
	Size         uint32
	Connection   *uint16
	Count, Error uint32
	Options      *winOption
}
type winState struct {
	Flags                   uint32
	Server, Bypass, AutoURL string
}
type windowsBackend struct{}

func newBackend(saved string) (backend, error) {
	if saved != "" && saved != "windows" {
		return nil, fmt.Errorf("unsupported snapshot backend %s", saved)
	}
	return windowsBackend{}, nil
}
func (windowsBackend) name() string { return "windows" }
func (windowsBackend) read(_ string) (string, error) {
	opts := []winOption{{Option: 10}, {Option: 2}, {Option: 3}, {Option: 4}}
	list := winOptions{Count: uint32(len(opts)), Options: &opts[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	ok, _, err := queryOption.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return "", fmt.Errorf("query Windows proxy: %w", err)
	}
	decode := func(option *winOption) string {
		p := *(*unsafe.Pointer)(unsafe.Pointer(&option.Value))
		if p == nil {
			return ""
		}
		defer globalFree.Call(uintptr(p))
		return windows.UTF16PtrToString((*uint16)(p))
	}
	s := winState{uint32(opts[0].Value), decode(&opts[1]), decode(&opts[2]), decode(&opts[3])}
	raw, _ := json.Marshal(s)
	return string(raw), nil
}
func (windowsBackend) write(_, value string) error {
	var state winState
	if err := json.Unmarshal([]byte(value), &state); err != nil {
		return err
	}
	var ptrs []*uint16
	for _, s := range []string{state.Server, state.Bypass, state.AutoURL} {
		p, err := windows.UTF16PtrFromString(s)
		if err != nil {
			return err
		}
		ptrs = append(ptrs, p)
	}
	opts := []winOption{{Option: 1, Value: uint64(state.Flags)}, {Option: 2, Value: uint64(uintptr(unsafe.Pointer(ptrs[0])))}, {Option: 3, Value: uint64(uintptr(unsafe.Pointer(ptrs[1])))}, {Option: 4, Value: uint64(uintptr(unsafe.Pointer(ptrs[2])))}}
	list := winOptions{Count: uint32(len(opts)), Options: &opts[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	ok, _, err := setOption.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	runtime.KeepAlive(ptrs)
	if ok == 0 {
		return fmt.Errorf("set Windows proxy: %w", err)
	}
	return nil
}
func (windowsBackend) refresh() error {
	for _, option := range []uintptr{39, 37} {
		ok, _, err := setOption.Call(0, option, 0, 0)
		if ok == 0 {
			return fmt.Errorf("refresh Windows proxy: %w", err)
		}
	}
	return nil
}
func (b windowsBackend) plan(host, port, service string) ([]change, error) {
	if service != "" {
		return nil, fmt.Errorf("--proxy-service applies only to macOS")
	}
	before, err := b.read("default")
	if err != nil {
		return nil, err
	}
	var state winState
	if err := json.Unmarshal([]byte(before), &state); err != nil {
		return nil, err
	}
	state.Flags = 3 // PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY; disable PAC and WPAD.
	addr := net.JoinHostPort(host, port)
	state.Server = "http=" + addr + ";https=" + addr
	after, _ := json.Marshal(state)
	return []change{{"default", before, string(after)}}, nil
}
