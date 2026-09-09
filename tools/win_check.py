#!/usr/bin/env python3
"""启动 TwinStar 并确认窗口真的出来了。

Tauri 窗口是 WebView2，标题前缀为 "TwinStar"。
用 ctypes 调 user32.EnumWindows，避免额外装 pywin32。
"""
import ctypes
import subprocess
import sys
import time

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D:\TwinStar\release\TwinStar.exe"
TITLE_HINT = "TwinStar"

user32 = ctypes.windll.user32
EnumWindows = user32.EnumWindows
GetWindowTextW = user32.GetWindowTextW
IsWindowVisible = user32.IsWindowVisible
GetWindowTextLengthW = user32.GetWindowTextLengthW

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def find_window():
    found = []

    def cb(hwnd, _lparam):
        if not IsWindowVisible(hwnd):
            return True
        length = GetWindowTextLengthW(hwnd)
        if length == 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
        if TITLE_HINT.lower() in title.lower():
            found.append((hwnd, title))
        return True

    EnumWindows(EnumWindowsProc(cb), 0)
    return found


def main():
    print(f"启动: {EXE}")
    proc = subprocess.Popen([EXE])
    try:
        for i in range(1, 16):
            time.sleep(1)
            wins = find_window()
            if wins:
                for hwnd, title in wins:
                    print(f"  ✅ 窗口已出现: hwnd={hwnd} 标题={title!r}")
                print("RESULT=OK")
                return
            if proc.poll() is not None:
                print(f"  ❌ 进程已退出，退出码={proc.returncode}")
                break
            print(f"  等待窗口... {i}s")
        print("RESULT=NO_WINDOW")
    finally:
        # 验证完把进程关掉，免得留个孤立窗口
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
