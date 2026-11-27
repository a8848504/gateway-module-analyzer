package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gateway-module-analyzer/internal/update"
)

const progressSetPosition = 0x0402 // PBM_SETPOS

func (a *application) showDownloadControls(show bool) {
	state := uintptr(0)
	if show {
		state = 5 // SW_SHOW
	}
	showWindow := user32.NewProc("ShowWindow")
	showWindow.Call(a.progressBar, state)
	showWindow.Call(a.cancelUpdateButton, state)
	enabled(a.cancelUpdateButton, show)
}

func (a *application) showDownloadProgress(progress update.DownloadProgress) {
	received := min(progress.Received, progress.Total)
	percent := int(received * 100 / progress.Total)
	send.Call(a.progressBar, progressSetPosition, uintptr(percent), 0)
	switch {
	case progress.Verifying:
		text(a.status, "下载完成，正在校验 SHA-256…")
	case received == 0 && progress.Attempt > 1:
		text(a.status, "正在连接备用下载地址…")
	case received == 0:
		text(a.status, "正在连接 GitHub 下载地址…")
	default:
		const mib = 1 << 20
		text(a.status, fmt.Sprintf("正在下载更新  %d%%  ·  %.2f / %.2f MiB",
			percent, float64(received)/mib, float64(progress.Total)/mib))
	}
}

func (a *application) requestDownloadCancel() {
	if a.cancelDownload != nil {
		a.cancelDownload()
		enabled(a.cancelUpdateButton, false)
		text(a.status, "正在取消下载…")
	}
}

func (a *application) beginUpdateDownload(github *update.GitHub, release *update.Release) {
	target, err := os.Executable()
	if err != nil {
		a.updateFailed("无法确定当前程序位置", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelDownload = cancel
	a.showDownloadProgress(update.DownloadProgress{Attempt: 1, Total: release.Size})
	a.showDownloadControls(true)
	go func() {
		var lastUpdate time.Time
		candidate, err := github.Download(ctx, release, filepath.Dir(target), func(progress update.DownloadProgress) {
			if progress.Received != 0 && progress.Received < progress.Total &&
				time.Since(lastUpdate) < 200*time.Millisecond {
				return
			}
			lastUpdate = time.Now()
			a.post(func() {
				if ctx.Err() == nil {
					a.showDownloadProgress(progress)
				}
			})
		})
		a.post(func() {
			cancelled := ctx.Err() != nil || errors.Is(err, context.Canceled)
			cancel()
			a.cancelDownload = nil
			if cancelled {
				if candidate != "" {
					os.Remove(candidate)
				}
				a.showDownloadControls(false)
				a.setBusy(false)
				text(a.status, "已取消下载")
				if a.closing {
					user32.NewProc("DestroyWindow").Call(a.window)
				}
				return
			}
			if err != nil {
				a.updateFailed("下载更新失败", err)
				return
			}
			send.Call(a.progressBar, progressSetPosition, 100, 0)
			enabled(a.cancelUpdateButton, false)
			text(a.status, "校验通过，正在准备安装与重启…")
			go a.installDownloadedUpdate(target, candidate, release.Digest)
		})
	}()
}

func (a *application) installDownloadedUpdate(target, candidate, digest string) {
	err := update.StartReplacement(target, candidate, digest)
	if err != nil {
		os.Remove(candidate)
	}
	a.post(func() {
		if err != nil {
			a.updateFailed("安装更新失败", err)
			return
		}
		user32.NewProc("DestroyWindow").Call(a.window)
	})
}

func (a *application) updateFailed(title string, err error) {
	a.showDownloadControls(false)
	a.setBusy(false)
	text(a.status, title)
	messageBox(a.window, title, err.Error()+"\r\n\r\n也可以从 GitHub 发行页下载新版。", 0x30)
}
