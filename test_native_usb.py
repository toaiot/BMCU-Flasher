# -*- coding: utf-8 -*-
"""Native USB 模式回归测试（canonical 命令：python test_native_usb.py，零依赖，无 pytest 也可跑）。

覆盖：API 面、i18n、USB 帧解析单测（mock 传输）、flash_firmware 错误路径、
re-enter 分支回归（native_usb 曾错误落入 ttl 分支）、CLI --list 实跑、
CLI/GUI 接线、py_compile、真机非破坏性握手（设备在 bootloader 时才执行，否则 SKIP）。
"""
import glob
import json
import os
import py_compile
import subprocess
import sys
import tempfile

REPO = r"C:\Users\wbjy3\Documents\Hermers\BMCU-Flasher"
sys.path.insert(0, REPO)

passed, failed, skipped = [], [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))


def skip(name, detail=""):
    skipped.append(name)
    print(f"  SKIP  {name}  [{detail}]")


import bmcu_flasher as bf

print("== 1. API surface ==")
check("WchIspUsb class exists", hasattr(bf, "WchIspUsb"))
check("list_usb_isp_devices callable", callable(getattr(bf, "list_usb_isp_devices", None)))
check("USB_ISP_PID == 0x55E0", getattr(bf, "USB_ISP_PID", None) == 0x55E0)

print("== 2. i18n keys (12 languages) ==")
new_keys = ["mode_native_usb", "help_nusb_title", "help_nusb_s1", "help_nusb_s2",
            "nusb_status_ok", "nusb_status_none", "flash_done_nusb"]
for path in sorted(glob.glob(os.path.join(REPO, "i18n", "*.json"))):
    lang = os.path.splitext(os.path.basename(path))[0]
    d = json.load(open(path, encoding="utf-8"))
    missing = [k for k in new_keys if not str(d.get(k, "")).strip()]
    check(f"i18n/{lang} has {len(new_keys)} keys", not missing, str(missing))
    check(f"i18n/{lang} nusb_status_ok has {{dev}}", "{dev}" in str(d.get("nusb_status_ok", "")),
          "missing {dev} placeholder")

print("== 3. USB frame parse unit test (mock transport) ==")


class MockUsb:
    def __init__(self, rx):
        self.rx = rx
        self.tx = b""

    def _write_read(self, raw_tx, timeout_s):
        self.tx = raw_tx
        return self.rx


ident = bf.build_identify(bf.BMCU_DEVICE_ID, bf.BMCU_DEVICE_TYPE)
isp = bf.WchIspUsb()
m = MockUsb(bytes([0xA1, 0x00, 0x02, 0x00, 0x31, 0x19]))
isp._write_read = m._write_read
code, data = isp.txrx(ident, bf.CMD_IDENTIFY, 1.0)
check("txrx strips 57AB+checksum", m.tx == ident[2:-1], m.tx.hex())
check("txrx parses code/data", code == 0x00 and data == bytes([0x31, 0x19]), f"{code} {data.hex()}")

try:
    isp.txrx(ident, 0xA7, 1.0)
    check("cmd mismatch raises", False)
except RuntimeError:
    check("cmd mismatch raises", True)

m2 = MockUsb(b"\xa1\x00")
isp._write_read = m2._write_read
try:
    isp.txrx(ident, bf.CMD_IDENTIFY, 1.0)
    check("short response raises", False)
except TimeoutError:
    check("short response raises", True)

print("== 4. flash_firmware error paths ==")
dummy = os.path.join(tempfile.gettempdir(), "hermes-verify-dummy.bin")
with open(dummy, "wb") as f:
    f.write(bytes(range(256)) * 128)  # 32KB：让 4b 的 program 阶段有真实耗时（避免 dt=0 除零）

try:
    bf.flash_firmware(firmware_path="C:/definitely/missing.bin", mode="native_usb", port="")
    check("missing fw -> FileNotFoundError", False)
except FileNotFoundError:
    check("missing fw -> FileNotFoundError", True)

try:
    bf.flash_firmware(firmware_path=dummy, mode="bogus", port="")
    check("bad mode -> ValueError", False)
except ValueError:
    check("bad mode -> ValueError", True)

try:
    bf.flash_firmware(firmware_path=dummy, mode="ttl", port="")
    check("ttl without port -> RuntimeError", False)
except RuntimeError as e:
    check("ttl without port -> RuntimeError", "requires --port" in str(e), str(e))

orig_open, orig_sleep = bf.WchIspUsb.open, bf.time.sleep
bf.WchIspUsb.open = lambda self: (_ for _ in ()).throw(RuntimeError("mock: no device"))
bf.time.sleep = lambda s: None
try:
    bf.flash_firmware(firmware_path=dummy, mode="native_usb", port="")
    check("native_usb wait-loop timeout msg", False, "completed unexpectedly")
except RuntimeError as e:
    check("native_usb wait-loop timeout msg", "identify failed (native_usb)" in str(e), str(e))
finally:
    bf.WchIspUsb.open, bf.time.sleep = orig_open, orig_sleep

print("== 4b. re-enter branch regression (end-to-end mock, issue: native_usb fell into ttl branch) ==")


class FakeIsp:
    """模拟 WchIspUsb：isp_end(01) 后 USB 重枚举（前 3 次 open 失败），其余命令全 OK。"""

    instances = []

    def __init__(self, trace=False):
        self.open_count = 0
        self.isp_end_calls = 0
        self.baud = 115200  # flash_firmware 的 identify 日志会访问 isp.baud
        self.cfg12 = bytes([0xFF, 0xFF, 0x3F, 0xC0, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        self.uid = bytes(range(8))
        # calc_xor_key_uid(uid, 0x31) 的校验和：s=0x1C, k=[0x1C]*8, k[7]=0x4D, sum=0x11
        self.boot_sum = 0x11
        FakeIsp.instances.append(self)

    def open(self):
        self.open_count += 1
        if self.isp_end_calls >= 1 and self.open_count <= 3:
            raise RuntimeError("mock: device absent (re-enumerating)")

    def close(self):
        pass

    def flush(self):
        pass

    def set_baud(self, b):
        pass

    def txrx(self, pkt, expect_cmd, timeout_s):
        if expect_cmd == bf.CMD_ISP_END:
            self.isp_end_calls += 1
        if expect_cmd == bf.CMD_IDENTIFY:
            return 0x00, bytes([bf.BMCU_DEVICE_ID, bf.BMCU_DEVICE_TYPE])
        if expect_cmd == bf.CMD_READ_CFG:
            return 0x00, b"\x00\x00" + self.cfg12 + self.uid
        if expect_cmd == bf.CMD_ISP_KEY:
            return 0x00, bytes([self.boot_sum, 0x00])
        return 0x00, b""


logs = []
orig_cls = bf.WchIspUsb
bf.WchIspUsb = FakeIsp  # 不 patch time.sleep：真实延时避免 program 耗时 0s 触发 kb/dt 除零
try:
    bf.flash_firmware(firmware_path=dummy, mode="native_usb", port="",
                      log_cb=lambda l, m: logs.append(m))
    done, err = True, ""
except Exception as e:
    done, err = False, str(e)
finally:
    bf.WchIspUsb = orig_cls
joined = "\n".join(logs)
isp_last = FakeIsp.instances[-1]
check("re-enter uses native_usb branch", "waiting for USB device to re-enumerate" in joined, joined[-400:])
check("re-enter NOT ttl branch", "ttl: re-enter bootloader now" not in joined, joined[-400:])
check("full flow completes (OK total)", done and "OK total=" in joined, err)
check("re-enter re-opened device", isp_last.open_count >= 4, f"open_count={isp_last.open_count}")
check("done message mentions 24V/calibration", "24V" in joined and "calibration" in joined, joined[-300:])

print("== 5. CLI --list real run ==")
r = subprocess.run([sys.executable, os.path.join(REPO, "bmcu_flasher.py"), "x.bin",
                    "--mode", "native_usb", "--list"],
                   capture_output=True, text=True, timeout=30)
out = (r.stdout or "") + (r.stderr or "")
if bf.list_usb_isp_devices():
    check("CLI --list finds device", "WCH-ISP" in out, out.strip())
else:
    skip("CLI --list finds device", "no device in bootloader")

print("== 6. CLI / GUI wiring (source-level) ==")
cli_src = open(os.path.join(REPO, "bmcu_flasher.py"), encoding="utf-8").read()
gui_src = open(os.path.join(REPO, "bmcu_flasher_gui.py"), encoding="utf-8").read()
check("CLI mode choices", '["usb", "ttl", "native_usb"]' in cli_src)
check("CLI --list native_usb branch", 'args.mode == "native_usb"' in cli_src)
check("GUI radio value", 'value="native_usb"' in gui_src)
check("GUI mode validation", '("usb", "ttl", "native_usb")' in gui_src)
check("GUI port check relaxed", 'self.var_mode.get() != "native_usb"' in gui_src)
check("GUI hint covers native_usb", 'in ("ttl", "native_usb")' in gui_src)
check("GUI help section", "help_nusb_title" in gui_src)
check("GUI hides port row in native_usb", "_row_port_lbl" in gui_src and "_row_port_btns" in gui_src)
check("GUI device status row", "_refresh_nusb_status" in gui_src and "nusb_status_ok" in gui_src)

print("== 7. py_compile ==")
try:
    py_compile.compile(os.path.join(REPO, "bmcu_flasher.py"), doraise=True)
    py_compile.compile(os.path.join(REPO, "bmcu_flasher_gui.py"), doraise=True)
    check("py_compile both modules", True)
except Exception as e:
    check("py_compile both modules", False, str(e))

print("== 8. real-chip non-destructive handshake ==")
if not bf.list_usb_isp_devices():
    skip("real-chip identify/read_cfg/isp_key", "WCH ISP 设备不在 bootloader（未插入/已复位）")
else:
    try:
        t = bf.WchIspUsb()
        t.open()
        c1, d1 = t.txrx(bf.build_identify(bf.BMCU_DEVICE_ID, bf.BMCU_DEVICE_TYPE), bf.CMD_IDENTIFY, 1.0)
        c2, d2 = t.txrx(bf.build_read_cfg(bf.BMCU_CFG_MASK), bf.CMD_READ_CFG, 1.2)
        c3, d3 = t.txrx(bf.build_isp_key(b"\x00" * 0x1E), bf.CMD_ISP_KEY, 1.2)
        t.close()
        ok = (c1 == 0x00 and d1[:2] == bytes([bf.BMCU_DEVICE_ID, bf.BMCU_DEVICE_TYPE])
              and c2 == 0x00 and len(d2) >= 14 and c3 == 0x00)
        check("real-chip identify/read_cfg/isp_key", ok,
              f"c1={c1} d1={d1.hex()} c2={c2} c3={c3}")
    except Exception as e:
        check("real-chip identify/read_cfg/isp_key", False, str(e))

try:
    os.remove(dummy)
except OSError:
    pass

print("== 9. GUI instantiation (tkinter: native_usb layout switch) ==")
app = None
try:
    import bmcu_flasher_gui as g

    cfg_backup = None
    if os.path.exists(g._cfg_path()):
        with open(g._cfg_path(), encoding="utf-8") as f:
            cfg_backup = f.read()

    app = g.App()
    check("GUI App() constructs", True)

    def mapped(w):
        return bool(w is not None and w.grid_info())

    # 切到 native_usb
    app.var_mode.set("native_usb")
    app._apply_mode_layout(init=False)
    app.update_idletasks()
    check("native_usb: port row hidden",
          not mapped(app._row_port_lbl) and not mapped(app._row_port_cell) and not mapped(app._row_port_btns),
          f"port lbl/cell/btns grid_info={mapped(app._row_port_lbl)}/{mapped(app._row_port_cell)}/{mapped(app._row_port_btns)}")
    check("native_usb: nusb row visible", mapped(app._nusb_row))
    check("native_usb: status not-detected text", "WCH ISP" in str(app._nusb_status.cget("text")))

    # mock 设备存在 → 状态显示设备
    orig_list = bf.list_usb_isp_devices
    bf.list_usb_isp_devices = lambda: ["WCH-ISP ch375#0 (4348:55E0)"]
    try:
        app._refresh_nusb_status()
        check("native_usb: status detected text", "WCH-ISP ch375#0" in str(app._nusb_status.cget("text")),
              str(app._nusb_status.cget("text")))
    finally:
        bf.list_usb_isp_devices = orig_list

    # 切回 usb 模式
    app.var_mode.set("usb")
    app._apply_mode_layout(init=False)
    app.update_idletasks()
    check("usb: port row visible", mapped(app._row_port_lbl) and mapped(app._row_port_cell))
    check("usb: nusb row hidden", not mapped(app._nusb_row))

    app.destroy()
    app = None
    if cfg_backup is not None:
        with open(g._cfg_path(), "w", encoding="utf-8") as f:
            f.write(cfg_backup)
except Exception as e:
    check("GUI instantiation", False, f"{type(e).__name__}: {e}")
    if app is not None:
        try:
            app.destroy()
        except Exception:
            pass

print("== 10. _MEIPASS DLL fallback + release.yml packaging ==")


class _FakeDll:
    def __init__(self, name):
        self.name = name

    def __getattr__(self, n):
        def _f(*a, **k):
            return True
        return _f


attempts = []
orig_windll, orig_meipass = bf.ctypes.WinDLL, getattr(sys, "_MEIPASS", None)


def _fake_windll(name):
    attempts.append(name)
    if len(attempts) == 1:
        raise OSError("mock: system lookup failed")
    return _FakeDll(name)


try:
    bf.ctypes.WinDLL = _fake_windll
    sys._MEIPASS = "C:/fake_meipass"
    dll = bf._ch375_dll()
    exp = os.path.normpath("C:/fake_meipass/CH375DLL64.dll")
    check("_MEIPASS fallback loads bundled DLL",
          dll is not None and os.path.normpath(attempts[-1]) == exp, str(attempts))
finally:
    bf.ctypes.WinDLL = orig_windll
    if orig_meipass is None:
        sys.__dict__.pop("_MEIPASS", None)
    else:
        sys._MEIPASS = orig_meipass

yml_path = os.path.join(REPO, ".github", "workflows", "release.yml")
yml = open(yml_path, encoding="utf-8").read()
check("release.yml: pyusb+libusb deps", "pyusb libusb-package" in yml)
check("release.yml: collect-all usb/libusb_package", "--collect-all usb" in yml and "--collect-all libusb_package" in yml)
check("release.yml: bundle CH375DLL64.dll", '--add-binary "CH375DLL64.dll;."' in yml)
check("CH375DLL64.dll asset in repo", os.path.isfile(os.path.join(REPO, "CH375DLL64.dll")))

print("\n==== SUMMARY ====")
print(f"PASS={len(passed)} FAIL={len(failed)} SKIP={len(skipped)}")
for f in failed:
    print(f"  FAILED: {f}")
sys.exit(1 if failed else 0)
