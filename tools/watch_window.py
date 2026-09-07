import ctypes, ctypes.wintypes as wt, subprocess, time, sys

EXE = r"D:\TwinStar\release\TwimStar.exe"

def find_window():
    res = []
    def cb(h, l):
        buf = ctypes.create_unicode_buffer(256)
        ctypes.windll.user32.GetWindowTextW(h, buf, 256)
        if 'TwimStar' in buf.value:
            res.append((h, buf.value, ctypes.windll.user32.IsWindowVisible(h)))
        return True
    CB = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)(cb)
    ctypes.windll.user32.EnumWindows(CB, 0)
    return res

proc = subprocess.Popen([EXE], cwd=r"D:\TwinStar\release")
print(f"启动 PID={proc.pid}")
alive_shown = False
for i in range(25):
    time.sleep(1)
    win = find_window()
    exited = proc.poll() is not None
    line = f"t={i+1}s 窗口={win if win else '无'} 进程={'退出(code='+str(proc.poll())+')' if exited else '运行中'}"
    print(line, flush=True)
    if win:
        alive_shown = True
    if exited:
        break
print("结论:", "窗口出现过" if alive_shown else "窗口从未出现")
