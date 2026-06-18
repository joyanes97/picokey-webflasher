import hashlib
import json
import os
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from picoboot.picoboot import PicoBoot


BASE = Path(os.environ.get("PICOKEY_DATA", "/opt/picokey-web/data"))
IMAGES = Path(os.environ.get("PICOKEY_IMAGES", "/opt/picokey-web/images"))
MANIFEST = Path(os.environ.get("PICOKEY_MANIFEST", "/opt/picokey-web/pico_boards_manifest.json"))
BUILD_SCRIPT = Path(os.environ.get("PICOKEY_BUILD_SCRIPT", "/opt/picokey-web/build-pico-fido.sh"))
BUILD_ROOT = Path(os.environ.get("PICOKEY_BUILD_ROOT", "/opt/picokey-web/build"))
for directory in (BASE, IMAGES, BUILD_ROOT):
    directory.mkdir(parents=True, exist_ok=True)

UF2_MAGIC = 0x0A324655
UF2_MAGIC2 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
XIP_BASE = 0x10000000
FLASH_SECTOR = 4096
WRITE_PAGE = 256
KNOWN_VENDORS = {
    "Nitrokey HSM": (0x20A0, 0x4230),
    "Nitrokey FIDO2": (0x20A0, 0x42B1),
    "Nitrokey Pro": (0x20A0, 0x4108),
    "Nitrokey 3": (0x20A0, 0x42B2),
    "Nitrokey Start": (0x20A0, 0x4211),
    "Yubikey 4/5": (0x1050, 0x0407),
    "Yubikey NEO": (0x1050, 0x0116),
    "Yubico YubiHSM": (0x1050, 0x0030),
    "FSIJ Gnuk": (0x234B, 0x0000),
    "GnuPG e.V.": (0x1209, 0x2440),
    "Pico Default": (0xFEFF, 0xFCFD),
}
PHY_LED_DRIVER = {"PICO": 0x01, "PIMORONI": 0x02, "WS2812": 0x03, "CYW43": 0x04, "NEOPIXEL": 0x05, "NONE": 0xFF}
PHY_OPT = {"WCID": 0x01, "DIMM": 0x02, "DISABLE_POWER_RESET": 0x04, "LED_STEADY": 0x08}
PHY_CURVE = {"SECP256R1": 0x01, "SECP384R1": 0x02, "SECP521R1": 0x04, "SECP256K1": 0x08, "BP256R1": 0x10, "BP384R1": 0x20, "BP512R1": 0x40, "ED25519": 0x80, "ED448": 0x100, "CURVE25519": 0x200, "CURVE448": 0x400}
PHY_USB_ITF = {"CCID": 0x01, "WCID": 0x02, "HID": 0x04, "KB": 0x08}
DEFAULT_BOARD = {"name": "tenstar", "platform": "rp2350", "flash_size_bytes": 16 * 1024 * 1024, "led_driver": "ws2812", "led_pin": 22}

app = FastAPI(title="PicoKey Web Flasher")
lock = threading.Lock()
jobs: list[dict[str, Any]] = []


def log(msg: str) -> None:
    jobs.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "msg": msg})
    del jobs[:-300]


def load_boards() -> list[dict[str, Any]]:
    boards: list[dict[str, Any]] = []
    if MANIFEST.exists():
        data = json.loads(MANIFEST.read_text())
        boards = data.get("boards", [])
    if not any(b.get("name") == "tenstar" for b in boards):
        boards.insert(0, DEFAULT_BOARD)
    return boards


def selected_board() -> dict[str, Any]:
    selected = BASE / "selected-board.txt"
    name = selected.read_text().strip() if selected.exists() else "tenstar"
    return next((b for b in load_boards() if b.get("name") == name), DEFAULT_BOARD)


def parse_uf2(path: Path) -> list[tuple[int, bytes]]:
    raw = path.read_bytes()
    if len(raw) % 512:
        raise ValueError("UF2 size is not multiple of 512")
    blocks: dict[int, bytes] = {}
    for off in range(0, len(raw), 512):
        block = raw[off : off + 512]
        magic, magic2, _flags, addr, size, _block_no, _blocks_total, _family = struct.unpack("<IIIIIIII", block[:32])
        end_magic = struct.unpack("<I", block[508:512])[0]
        if magic != UF2_MAGIC or magic2 != UF2_MAGIC2 or end_magic != UF2_MAGIC_END:
            continue
        if size > 476:
            raise ValueError(f"invalid UF2 payload size {size}")
        blocks[addr] = block[32 : 32 + size]
    if not blocks:
        raise ValueError("no UF2 blocks found")
    return sorted(blocks.items())


def coalesce(blocks: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytearray]] = []
    for addr, data in blocks:
        if out and addr == out[-1][0] + len(out[-1][1]):
            out[-1][1].extend(data)
        else:
            out.append((addr, bytearray(data)))
    return [(addr, bytes(data)) for addr, data in out]


def align_down(value: int, size: int) -> int:
    return value - (value % size)


def align_up(value: int, size: int) -> int:
    return (value + size - 1) // size * size


def pad_write(data: bytes) -> bytes:
    return data + b"\xff" * ((WRITE_PAGE - len(data) % WRITE_PAGE) % WRITE_PAGE)


def save_image(name: str, data: bytes) -> Path:
    safe = "".join(c for c in name if c.isalnum() or c in "._-") or "firmware.uf2"
    if not safe.endswith(".uf2"):
        safe += ".uf2"
    digest = hashlib.sha256(data).hexdigest()[:12]
    path = IMAGES / f"{digest}-{safe}"
    path.write_bytes(data)
    return path


def stored_image(name: str) -> Path:
    safe = Path(name).name
    if safe != name or not safe.endswith(".uf2"):
        raise HTTPException(400, "invalid image name")
    return IMAGES / safe


def image_info(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    segments = coalesce(parse_uf2(path))
    latest = BASE / "latest.txt"
    return {
        "name": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "segments": [{"addr": hex(addr), "bytes": len(segment)} for addr, segment in segments],
        "uploaded": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime)),
        "latest": latest.exists() and latest.read_text().strip() == str(path),
    }


def list_images() -> list[dict[str, Any]]:
    out = []
    for path in sorted(IMAGES.glob("*.uf2"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            out.append(image_info(path))
        except Exception as exc:
            out.append({"name": path.name, "error": str(exc)})
    return out


def latest_image() -> Path:
    latest = BASE / "latest.txt"
    if not latest.exists():
        raise HTTPException(400, "upload or build image first")
    path = Path(latest.read_text().strip())
    if not path.exists():
        raise HTTPException(400, "latest image missing")
    parse_uf2(path)
    return path


def usb_devices() -> list[str]:
    try:
        out = subprocess.check_output(["lsusb"], text=True, timeout=2, stderr=subprocess.STDOUT)
        return [line for line in out.splitlines() if line.strip()]
    except Exception as exc:
        return [f"lsusb unavailable: {exc}"]


def build_firmware(board: str, fw_version: str, git_ref: str, clean: bool) -> dict[str, Any]:
    if not BUILD_SCRIPT.exists():
        raise HTTPException(500, f"build script missing: {BUILD_SCRIPT}")
    if board not in {b.get("name") for b in load_boards()}:
        raise HTTPException(404, "unknown board")
    if "." not in fw_version or not fw_version.replace(".", "", 1).isdigit():
        raise HTTPException(400, "firmware version must look like 7.7")
    cmd = [str(BUILD_SCRIPT), "--board", board, "--version", git_ref, "--fw-version", fw_version, "--no-flash", "--workdir", str(BUILD_ROOT)]
    if clean:
        cmd.append("--clean")
    log("build started: " + " ".join(cmd))
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=3600, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    for line in output.splitlines()[-60:]:
        log(line)
    if proc.returncode:
        raise HTTPException(500, {"error": "build failed", "returncode": proc.returncode, "tail": output.splitlines()[-80:]})
    candidates = sorted((BUILD_ROOT / "dist").glob(f"pico_fido_{board}_v{fw_version}.uf2"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        candidates = sorted((BUILD_ROOT / "dist").glob("*.uf2"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise HTTPException(500, "build finished but no UF2 found")
    saved = save_image(candidates[0].name, candidates[0].read_bytes())
    (BASE / "latest.txt").write_text(str(saved))
    log(f"built image {saved.name}")
    return image_info(saved)


def open_boot() -> PicoBoot:
    return PicoBoot.open()


def flash_uf2(path: Path, erase_all: bool, flash_size: int) -> dict[str, Any]:
    segments = coalesce(parse_uf2(path))
    with lock:
        pb = open_boot()
        try:
            pb.exclusive_access()
            pb.exit_xip()
            if erase_all:
                log(f"full erase: 0x0+0x{flash_size:x}")
                pb.flash_erase(0, flash_size)
            for addr, data in segments:
                flash_addr = addr - XIP_BASE if addr >= XIP_BASE else addr
                start = align_down(flash_addr, FLASH_SECTOR)
                end = align_up(flash_addr + len(data), FLASH_SECTOR)
                log(f"erase sector range 0x{start:08x}+0x{end-start:x}")
                pb.flash_erase(start, end - start)
                write = pad_write(data)
                log(f"write 0x{flash_addr:08x}+0x{len(write):x}")
                pb.flash_write(flash_addr, write)
            log("reboot")
            pb.reboot()
        finally:
            pb.close()
    return {"image": path.name, "erase_all": erase_all, "segments": [(hex(a), len(d)) for a, d in segments]}


def u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def phy_tlv(
    vid: int | None,
    pid: int | None,
    led_driver: str,
    led_pin: int | None,
    led_brightness: int | None,
    opts: int,
    up_btn: int | None,
    usb_product: str,
    enabled_curves: int | None,
    enabled_usb_itf: int | None,
) -> bytes:
    data = bytearray()
    if vid is not None and pid is not None:
        data += bytes([0x00, 0x04]) + u16be(vid) + u16be(pid)
    if led_pin is not None:
        data += bytes([0x04, 0x01, led_pin & 0xFF])
    if led_brightness is not None:
        data += bytes([0x05, 0x01, led_brightness & 0xFF])
    data += bytes([0x06, 0x02]) + u16be(opts)
    if up_btn is not None:
        data += bytes([0x08, 0x01, up_btn & 0xFF])
    if usb_product:
        enc = usb_product.encode("ascii", "ignore")[:14] + b"\x00"
        data += bytes([0x09, len(enc)]) + enc
    if enabled_curves is not None:
        data += bytes([0x0A, 0x04]) + u32be(enabled_curves)
    if enabled_usb_itf is not None:
        data += bytes([0x0B, 0x01, enabled_usb_itf & 0xFF])
    data += bytes([0x0C, 0x01, PHY_LED_DRIVER[led_driver]])
    return bytes(data)


def feature_stub(feature: str) -> dict[str, Any]:
    log(f"feature requested: {feature}")
    return {
        "ok": False,
        "feature": feature,
        "reason": "CTAP/APDU smart-card backend not ported yet. Firmware build/upload/upgrade/erase operations are active.",
        "private_use": "enabled",
    }


HTML = """
<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>PicoKeyApp Web</title><style>
:root{color-scheme:dark;--bg:#09090b;--panel:#18181b;--panel2:#111113;--hover:#27272a;--border:#ffffff1a;--text:#fafafa;--muted:#a1a1aa;--green:#16a34a;--red:#b91c1c;--amber:#d97706;--blue:#2563eb}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.app{min-height:100vh;display:grid;grid-template-columns:270px 1fr}.sidebar{background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:12px;padding:20px}.logo{width:40px;height:40px;border-radius:4px;background:linear-gradient(135deg,#7cff8a,#3ee6a6);display:grid;place-items:center;color:#3f3f46;font-weight:900}.menu{padding:0 12px;flex:1}.menu-title,.status-title{color:var(--muted);font-size:12px;margin:16px 0 8px 8px}.nav{display:flex;width:100%;padding:8px 10px;margin:4px 0;border:0;border-radius:8px;background:transparent;color:var(--text);font:inherit;text-align:left;cursor:pointer}.nav:hover,.nav.active{background:var(--hover)}.device-panel{border-top:1px solid var(--border);padding:12px;background:#111113}.badge,.pill{border-radius:999px;padding:2px 8px;font-size:11px;font-weight:700;background:#3f3f46;color:white}.badge.ok,.pill.ok{background:var(--green)}.pill.warn{background:var(--amber)}.topbar{height:46px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:flex-end;padding:0 18px;color:var(--muted)}.page{padding:28px;max-width:1220px}.hidden{display:none}.page-head h1{margin:0 0 6px;font-size:28px}.page-head p{margin:0 0 22px;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.card{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:16px}.card-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}.card-title{font-weight:800}.stack{display:grid;gap:10px}.row{display:flex;gap:10px;flex-wrap:wrap}.kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.kv label,.field span{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}select,input{width:100%;background:#09090b;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px}.primary,.secondary,.danger,.refresh{border:1px solid var(--border);border-radius:8px;padding:9px 11px;color:white;cursor:pointer;background:#27272a}.primary{background:var(--blue)}.danger{background:var(--red)}.note{color:var(--muted);margin:0}.warning{color:#fbbf24}.mono,pre{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:#050506;border:1px solid var(--border);border-radius:8px;padding:10px;overflow:auto}.list{display:grid;gap:10px}.item{border:1px solid var(--border);border-radius:10px;padding:10px;background:#0c0c0e}.mobile-tabs{display:none}@media(max-width:850px){.app{display:block}.menu{display:none}.mobile-tabs{display:flex;gap:8px;overflow:auto;padding:10px;border-bottom:1px solid var(--border)}.grid{grid-template-columns:1fr}.page{padding:18px}}
</style></head><body><div class='app'><aside class='sidebar'><div class='brand'><div class='logo'>PK</div><b>PicoKeyApp Web</b></div><nav class='menu'><p class='menu-title'>PicoKeyApp</p><button class='nav active' data-view='home' onclick='show("home")'>Home</button><button class='nav' data-view='firmware' onclick='show("firmware")'>Firmware</button><button class='nav' data-view='config' onclick='show("config")'>Configuration</button><button class='nav' data-view='security' onclick='show("security")'>Security</button><button class='nav' data-view='audit' onclick='show("audit")'>Audit</button><p class='menu-title'>Applications</p><button class='nav' data-view='fido' onclick='show("fido")'>FIDO</button><button class='nav' data-view='hsm' onclick='show("hsm")'>PicoHSM</button><button class='nav' data-view='openpgp' onclick='show("openpgp")'>OpenPGP / PIV</button><p class='menu-title'>Help</p><button class='nav' data-view='about' onclick='show("about")'>About / Diagnostics</button></nav><div class='device-panel'><div class='row' style='justify-content:space-between'><span class='status-title'>Device</span><span id='sideBadge' class='badge'>Offline</span></div><button class='refresh' onclick='refresh()'>Refresh</button></div></aside><main><div class='topbar'>PicoKeyApp Web</div><div class='mobile-tabs'><button class='nav active' data-view='home' onclick='show("home")'>Home</button><button class='nav' data-view='firmware' onclick='show("firmware")'>Firmware</button><button class='nav' data-view='config' onclick='show("config")'>Config</button><button class='nav' data-view='fido' onclick='show("fido")'>FIDO</button></div>
<section id='home' class='page'><div class='page-head'><h1>Device Overview</h1><p>Status, target board, images, and safe operations.</p></div><div class='grid'><div class='card'><div class='card-head'><div class='card-title'>Device Information</div><span id='devPill' class='pill'>Checking</span></div><div class='kv'><div><label>Install mode</label><div id='bootMode'>Unknown</div></div><div><label>USB devices</label><div id='usbCount'>0</div></div><div><label>Target board</label><div id='boardName'>tenstar</div></div><div><label>Images</label><div id='imageCount'>0</div></div></div><div class='mono' id='status' style='margin-top:12px'>Loading...</div></div><div class='card'><div class='card-head'><div class='card-title'>Target Board</div><span class='pill' id='boardMeta'></span></div><label class='field'><span>Board</span><select id='boards' onchange='selectBoard()'></select></label><p class='note'>PicoKeyApp manifest. Tenstar: RP2350, 16MB, WS2812 GPIO 22.</p></div></div></section>
<section id='firmware' class='page hidden'><div class='page-head'><h1>Firmware</h1><p>Create UF2, upload UF2, upgrade preserving data, or erase and clean-install.</p></div><div class='grid'><div class='card'><div class='card-head'><div class='card-title'>Create Image</div><span class='pill ok'>pico-fido</span></div><div class='stack'><label class='field'><span>Firmware version</span><input id='fwVersion' value='7.7'></label><label class='field'><span>Git ref</span><input id='gitRef' value='v7.6'></label><label class='field'><span>Build board</span><select id='buildBoard'></select></label><div class='row'><button class='primary' onclick='buildImage(false)'>Build UF2</button><button class='secondary' onclick='buildImage(true)'>Clean build UF2</button></div><p class='note'>Build enables EdDSA/SHA3 and Tenstar board parameters.</p></div></div><div class='card'><div class='card-head'><div class='card-title'>Install</div><span class='pill warn'>confirm required</span></div><div class='stack'><button class='primary' onclick='flash(false)'>Upgrade firmware, keep data</button><button class='danger' onclick='flash(true)'>Erase all data + install</button><p class='warning'>Upgrade writes only UF2 sectors. Erase wipes credentials, PIN, and counters.</p></div></div><div class='card'><div class='card-head'><div class='card-title'>UF2 Images</div><button class='secondary' onclick='refreshImages()'>Reload</button></div><form id='up' class='stack'><input type='file' name='file' accept='.uf2'><button class='primary'>Upload UF2</button></form><div id='images' class='list' style='margin-top:14px'></div></div><div class='card'><div class='card-head'><div class='card-title'>Commission PHY</div></div><div class='stack'><label class='field'><span>Known vendor</span><select id='vendorPreset'></select></label><label class='field'><span>LED driver</span><select id='ledDriver'><option>WS2812</option><option>PICO</option><option>PIMORONI</option><option>CYW43</option><option>NEOPIXEL</option><option>NONE</option></select></label><label class='field'><span>LED GPIO</span><input id='ledPin' type='number' value='22'></label><label class='field'><span>LED brightness</span><input id='ledBrightness' type='number' value='255'></label><label class='field'><span>Presence button timeout</span><input id='upBtn' type='number' value='15'></label><label class='field'><span>USB product override</span><input id='usbProduct' placeholder='max 14 chars'></label><button class='secondary' onclick='commission()'>Generate PHY blob</button></div></div></div></section>
<section id='config' class='page hidden'><div class='page-head'><h1>Configuration</h1><p>PicoKeyApp Configuration panel: PHY, VID/PID, USB strings, LED, touch, and timeout settings.</p></div><div class='grid'><div class='card'><div class='card-head'><div class='card-title'>Device PHY</div><span class='pill'>read/write</span></div><div class='row'><button class='secondary' onclick='feature("config-read-phy")'>Read current PHY</button><button class='primary' onclick='feature("config-write-phy")'>Write PHY to device</button><button class='secondary' onclick='commission()'>Generate PHY blob</button></div><p class='note'>PHY blob generation now uses same tags/options as pypicokey PhyData.</p></div><div class='card'><div class='card-title'>Vendor / VID:PID</div><div class='stack'><label class='field'><span>Known vendor</span><select id='vidpidPreset' onchange='vendorPreset.value=this.value'></select></label><label class='field'><span>Custom VID</span><input id='customVid' placeholder='20a0'></label><label class='field'><span>Custom PID</span><input id='customPid' placeholder='42b1'></label><label class='field'><span>Product name</span><input id='productName' value='pico_fido' maxlength='14'></label><button class='primary' onclick='commission()'>Apply to PHY blob</button></div></div><div class='card'><div class='card-title'>LED</div><div class='stack'><label class='field'><span>Driver</span><select onchange='ledDriver.value=this.value'><option>WS2812</option><option>PICO</option><option>PIMORONI</option><option>CYW43</option><option>NEOPIXEL</option><option>NONE</option></select></label><label class='field'><span>GPIO</span><input onchange='ledPin.value=this.value' type='number' value='22'></label><label class='field'><span>Brightness</span><input onchange='ledBrightness.value=this.value' type='number' value='255'></label><label><input id='ledDimmable' type='checkbox'> LED dimmable</label><label><input id='ledSteady' type='checkbox'> LED steady</label></div></div><div class='card'><div class='card-title'>Options</div><div class='stack'><label class='field'><span>Presence button timeout</span><input id='upBtnConfig' onchange='upBtn.value=this.value' type='number' value='15'></label><label><input id='powerCycleReset' type='checkbox' checked> Enable power-cycle reset</label><label><input id='secp256k1' type='checkbox'> Enable secp256k1</label><label><input id='usbCcid' type='checkbox' checked> USB CCID</label><label><input id='usbWcid' type='checkbox' checked> USB WCID</label><label><input id='usbHid' type='checkbox' checked> USB HID</label><label><input id='usbKb' type='checkbox' checked> USB Keyboard</label></div></div></div></section>
<section id='security' class='page hidden'><div class='page-head'><h1>Security</h1><p>PicoKeyApp Security panel: secure boot and secure lock actions.</p></div><div class='grid'><div class='card'><div class='card-head'><div class='card-title'>Secure Boot</div><span class='pill warn'>irreversible path</span></div><div class='row'><button class='secondary' onclick='feature("security-read-state")'>Read security state</button><button class='secondary' onclick='dangerFeature("security-enable-secure-boot","SECURE")'>Enable secure boot</button></div></div><div class='card'><div class='card-head'><div class='card-title'>Secure Lock</div><span class='pill warn'>permanent</span></div><button class='danger' onclick='dangerFeature("security-secure-lock","LOCK")'>Permanently lock device</button><p class='warning'>Blocked by backend until PicoKeyApp secure path is fully ported and tested.</p></div></div></section>
<section id='fido' class='page hidden'><div class='page-head'><h1>FIDO</h1><p>PicoKeyApp FIDO area: Dashboard, Initialize, Session, Slots, Accounts, and Passkeys.</p></div><div class='grid'><div class='card'><div class='card-head'><div class='card-title'>Dashboard</div><span class='pill'>info</span></div><div class='row'><button class='secondary' onclick='feature("fido-dashboard-refresh")'>Refresh dashboard</button><button class='secondary' onclick='feature("fido-get-info")'>Get authenticator info</button></div></div><div class='card'><div class='card-head'><div class='card-title'>Initialize</div><span class='pill warn'>factory setup</span></div><div class='row'><button class='primary' onclick='feature("fido-initialize")'>Initialize FIDO</button><button class='secondary' onclick='feature("fido-reset")'>Reset FIDO</button></div></div><div class='card'><div class='card-title'>Session</div><div class='row'><button class='secondary' onclick='feature("fido-session-open")'>Open session</button><button class='secondary' onclick='feature("fido-session-close")'>Close session</button><button class='secondary' onclick='feature("fido-change-pin")'>Change PIN</button></div></div><div class='card'><div class='card-title'>Slots</div><div class='row'><button class='secondary' onclick='feature("fido-list-slots")'>List slots</button><button class='primary' onclick='feature("fido-write-slot")'>Write slot</button><button class='danger' onclick='dangerFeature("fido-delete-slot","DELETE")'>Delete slot</button></div></div><div class='card'><div class='card-title'>Accounts</div><div class='row'><button class='secondary' onclick='feature("fido-list-accounts")'>List accounts</button><button class='secondary' onclick='feature("fido-export-account")'>Export account</button></div></div><div class='card'><div class='card-title'>Passkeys</div><div class='row'><button class='secondary' onclick='feature("fido-unlock-passkeys")'>Unlock passkeys</button><button class='secondary' onclick='feature("fido-large-blob")'>Large blob</button><button class='secondary' onclick='feature("fido-permissions")'>Permissions</button><button class='danger' onclick='dangerFeature("fido-delete-passkey","DELETE")'>Delete passkey</button></div></div></div></section>
<section id='hsm' class='page hidden'><div class='page-head'><h1>PicoHSM</h1><p>PicoKeyApp HSM area: Initialize, Management, and HSM Crypto.</p></div><div class='grid'><div class='card'><div class='card-title'>Initialize</div><div class='row'><button class='primary' onclick='feature("hsm-initialize")'>Initialize HSM</button><button class='danger' onclick='dangerFeature("hsm-reset","RESET")'>Reset HSM</button></div></div><div class='card'><div class='card-title'>Management</div><div class='row'><button class='secondary' onclick='feature("hsm-list-objects")'>List objects</button><button class='secondary' onclick='feature("hsm-import-key")'>Import key</button><button class='secondary' onclick='feature("hsm-export-public")'>Export public key</button><button class='danger' onclick='dangerFeature("hsm-delete-object","DELETE")'>Delete object</button></div></div><div class='card'><div class='card-title'>HSM Crypto</div><div class='row'><button class='secondary' onclick='feature("hsm-sign")'>Sign</button><button class='secondary' onclick='feature("hsm-decrypt")'>Decrypt</button><button class='secondary' onclick='feature("hsm-attest")'>Attest</button></div></div></div></section>
<section id='openpgp' class='page hidden'><div class='page-head'><h1>OpenPGP / PIV</h1><p>PicoKeyApp OpenPGP management and PIV panel.</p></div><div class='grid'><div class='card'><div class='card-title'>OpenPGP Management</div><div class='row'><button class='secondary' onclick='feature("openpgp-status")'>Read status</button><button class='secondary' onclick='feature("openpgp-change-pin")'>Change PIN</button><button class='secondary' onclick='feature("openpgp-import-key")'>Import key</button><button class='danger' onclick='dangerFeature("openpgp-reset","RESET")'>Reset OpenPGP</button></div></div><div class='card'><div class='card-title'>PIV</div><div class='row'><button class='secondary' onclick='feature("piv-status")'>Read status</button><button class='secondary' onclick='feature("piv-generate-key")'>Generate key</button><button class='secondary' onclick='feature("piv-import-cert")'>Import certificate</button><button class='danger' onclick='dangerFeature("piv-reset","RESET")'>Reset PIV</button></div></div></div></section>
<section id='audit' class='page hidden'><div class='page-head'><h1>Audit</h1><p>PicoKeyApp Audit panel: events, state, and exports.</p></div><div class='grid'><div class='card'><div class='card-title'>Audit Log</div><div class='row'><button class='secondary' onclick='feature("audit-refresh")'>Refresh audit</button><button class='secondary' onclick='feature("audit-export")'>Export audit</button><button class='danger' onclick='dangerFeature("audit-clear","CLEAR")'>Clear audit</button></div></div><div class='card'><div class='card-title'>Verification</div><div class='row'><button class='secondary' onclick='feature("audit-verify-firmware")'>Verify firmware</button><button class='secondary' onclick='feature("audit-verify-config")'>Verify config</button></div></div></div></section>
<section id='about' class='page hidden'><div class='page-head'><h1>About / Diagnostics</h1><p>PicoKeyApp flow recreated for private browser use.</p></div><div class='grid'><div class='card'><div class='card-title'>About</div><div class='kv'><div><label>Firmware operations</label><div>Build, upload, upgrade, clean install</div></div><div><label>Default board</label><div>Tenstar RP2350 16MB</div></div><div><label>Safety</label><div>Typed confirmations</div></div><div><label>Mode</label><div>Private use</div></div></div></div><div class='card'><div class='card-head'><div class='card-title'>Diagnostics</div><button class='secondary' onclick='refreshJobs()'>Refresh log</button></div><pre id='out'></pre></div></div></section>
</main></div><script>
const $=id=>document.getElementById(id);const pages=['home','firmware','config','security','fido','hsm','openpgp','audit','about'];function pretty(x){return JSON.stringify(x,null,2)}async function api(url,opts={}){let r=await fetch(url,opts);let t=await r.text();try{$('out').textContent=pretty(JSON.parse(t))}catch{$('out').textContent=t}return r}function body(o){return new URLSearchParams(o).toString()}function show(id){for(let s of pages)$(s).classList.toggle('hidden',s!==id);document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===id))}
async function refresh(){let s=await fetch('/status').then(r=>r.json());$('status').textContent=pretty(s);$('bootMode').textContent=s.bootloader?'Ready for firmware install':'Application mode or disconnected';$('devPill').textContent=s.bootloader?'Install Ready':'Not Ready';$('devPill').className='pill '+(s.bootloader?'ok':'');$('sideBadge').textContent=s.bootloader?'Ready':'Offline';$('sideBadge').className='badge '+(s.bootloader?'ok':'');$('usbCount').textContent=(s.usb||[]).length;$('imageCount').textContent=s.images||0;if(s.board)$('boardName').textContent=s.board.name;await refreshBoards();await refreshVendors();await refreshImages()}
async function refreshBoards(){let data=await fetch('/boards').then(r=>r.json());let opts=data.boards.map(b=>`<option ${b.name===data.selected.name?'selected':''}>${b.name}</option>`).join('');$('boards').innerHTML=opts;$('buildBoard').innerHTML=opts;let b=data.selected;$('boardMeta').textContent=`${b.platform||'unknown'} / ${Math.round((b.flash_size_bytes||0)/1048576)}MB / ${b.led_driver||'none'}:${b.led_pin??'-'}`;$('boardName').textContent=b.name}
async function refreshVendors(){let data=await fetch('/vendors').then(r=>r.json());let opts=data.vendors.map(v=>`<option value="${v.name}">${v.name} (${v.vid}:${v.pid})</option>`).join('')+'<option value="Custom VID:PID">Custom VID:PID</option>';if($('vendorPreset'))$('vendorPreset').innerHTML=opts;if($('vidpidPreset'))$('vidpidPreset').innerHTML=opts}
async function selectBoard(){await api('/board',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({name:$('boards').value})});await refreshBoards()}async function refreshImages(){let data=await fetch('/images').then(r=>r.json());$('imageCount').textContent=data.length;$('images').innerHTML=data.map(i=>`<div class='item'><div class='row'><b>${i.name}</b>${i.latest?' <span class="pill ok">selected</span>':''}</div><div class=mono>${i.sha256||i.error}</div><div class=row style='margin-top:10px'><button class=secondary onclick='selectImage("${i.name}")'>Use</button><button class=danger onclick='deleteImage("${i.name}")'>Delete</button></div></div>`).join('')||'<div class=item>No UF2 uploaded or built</div>'}
up.onsubmit=async e=>{e.preventDefault();await api('/upload',{method:'POST',body:new FormData(up)});await refreshImages()};async function buildImage(clean){await api('/build',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({board:$('buildBoard').value,fw_version:$('fwVersion').value,git_ref:$('gitRef').value,clean})});await refreshImages()}async function selectImage(name){await api('/image/select',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({name})});await refreshImages()}async function deleteImage(name){if(prompt('Type DELETE to remove image')!=='DELETE')return;await api('/image/delete',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({name,confirm:'DELETE'})});await refreshImages()}async function flash(erase){let word=erase?'ERASE':'INSTALL';if(prompt(`Type ${word} to continue`)!==word)return;await api('/flash',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({erase_all:erase,confirm:word})})}async function commission(){let vendor=$('vendorPreset')?.value||$('vidpidPreset')?.value||'Pico Default';await api('/commission',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:body({vendor,vid:$('customVid')?.value||'',pid:$('customPid')?.value||'',led_driver:$('ledDriver')?.value||'WS2812',led_pin:$('ledPin')?.value||'22',led_brightness:$('ledBrightness')?.value||'255',led_dimmable:$('ledDimmable')?.checked||false,power_cycle_reset:$('powerCycleReset')?.checked??true,led_steady:$('ledSteady')?.checked||false,up_btn:$('upBtn')?.value||$('upBtnConfig')?.value||'15',usb_product:$('usbProduct')?.value||$('productName')?.value||'',secp256k1:$('secp256k1')?.checked||false,usb_ccid:$('usbCcid')?.checked??true,usb_wcid:$('usbWcid')?.checked??true,usb_hid:$('usbHid')?.checked??true,usb_kb:$('usbKb')?.checked??true})})}async function feature(name){await api('/feature/'+name,{method:'POST'})}async function dangerFeature(name,word){if(prompt('Type '+word+' to continue')!==word)return;await feature(name)}async function refreshJobs(){$('out').textContent=pretty(await fetch('/jobs').then(r=>r.json()))}setInterval(refreshJobs,4000);refresh();
</script></body></html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return HTML


@app.get("/status")
def status() -> dict[str, Any]:
    base = {"board": selected_board(), "images": len(list_images()), "usb": usb_devices()}
    try:
        pb = open_boot()
        try:
            return {**base, "bootloader": True, "memory": str(pb.memory)}
        finally:
            pb.close()
    except Exception as exc:
        return {**base, "bootloader": False, "error": str(exc)}


@app.get("/jobs")
def get_jobs() -> list[dict[str, Any]]:
    return jobs


@app.get("/boards")
def boards() -> dict[str, Any]:
    return {"selected": selected_board(), "boards": load_boards()}


@app.get("/vendors")
def vendors() -> dict[str, Any]:
    return {"vendors": [{"name": name, "vid": f"{vid:04x}", "pid": f"{pid:04x}"} for name, (vid, pid) in KNOWN_VENDORS.items()]}


@app.post("/board")
def set_board(name: str = Form(...)) -> dict[str, Any]:
    board = next((b for b in load_boards() if b.get("name") == name), None)
    if not board:
        raise HTTPException(404, "unknown board")
    (BASE / "selected-board.txt").write_text(name)
    log(f"selected board {name}")
    return {"selected": board}


@app.get("/images")
def images() -> list[dict[str, Any]]:
    return list_images()


@app.post("/upload")
async def upload(file: UploadFile = File(...)) -> JSONResponse:
    data = await file.read()
    path = save_image(file.filename or "firmware.uf2", data)
    try:
        parse_uf2(path)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    (BASE / "latest.txt").write_text(str(path))
    log(f"uploaded {path.name}")
    return JSONResponse(image_info(path))


@app.post("/build")
def build(board: str = Form("tenstar"), fw_version: str = Form("7.7"), git_ref: str = Form("v7.6"), clean: bool = Form(False)) -> dict[str, Any]:
    return build_firmware(board, fw_version, git_ref, clean)


@app.post("/image/select")
def select_image(name: str = Form(...)) -> dict[str, Any]:
    path = stored_image(name)
    if not path.exists():
        raise HTTPException(404, "image missing")
    parse_uf2(path)
    (BASE / "latest.txt").write_text(str(path))
    log(f"selected image {path.name}")
    return image_info(path)


@app.post("/image/delete")
def delete_image(name: str = Form(...), confirm: str = Form("")) -> dict[str, Any]:
    if confirm != "DELETE":
        raise HTTPException(400, "type DELETE to delete image")
    path = stored_image(name)
    if not path.exists():
        raise HTTPException(404, "image missing")
    path.unlink()
    latest = BASE / "latest.txt"
    if latest.exists() and latest.read_text().strip() == str(path):
        latest.unlink()
    log(f"deleted image {name}")
    return {"deleted": name}


@app.post("/flash")
def flash(erase_all: bool = Form(False), confirm: str = Form("")) -> dict[str, Any]:
    expected = "ERASE" if erase_all else "INSTALL"
    if confirm != expected:
        raise HTTPException(400, f"type {expected} to continue")
    board = selected_board()
    return flash_uf2(latest_image(), erase_all, int(board.get("flash_size_bytes") or DEFAULT_BOARD["flash_size_bytes"]))


@app.post("/commission")
def commission(
    vendor: str = Form("Pico Default"),
    vid: str = Form(""),
    pid: str = Form(""),
    led_driver: str = Form("WS2812"),
    led_pin: int = Form(22),
    led_brightness: int = Form(255),
    led_dimmable: bool = Form(False),
    power_cycle_reset: bool = Form(True),
    led_steady: bool = Form(False),
    up_btn: int = Form(15),
    usb_product: str = Form(""),
    secp256k1: bool = Form(False),
    usb_ccid: bool = Form(True),
    usb_wcid: bool = Form(True),
    usb_hid: bool = Form(True),
    usb_kb: bool = Form(True),
) -> dict[str, Any]:
    led_driver = led_driver.upper()
    if led_driver not in PHY_LED_DRIVER:
        raise HTTPException(400, "invalid led_driver")
    if vendor in KNOWN_VENDORS:
        parsed_vid, parsed_pid = KNOWN_VENDORS[vendor]
    elif vid and pid:
        parsed_vid, parsed_pid = int(vid, 16), int(pid, 16)
    else:
        parsed_vid, parsed_pid = None, None
    opts = 0
    if led_dimmable:
        opts |= PHY_OPT["DIMM"]
    if not power_cycle_reset:
        opts |= PHY_OPT["DISABLE_POWER_RESET"]
    if led_steady:
        opts |= PHY_OPT["LED_STEADY"]
    curves = PHY_CURVE["SECP256K1"] if secp256k1 else None
    usb_itf = 0
    usb_itf |= PHY_USB_ITF["CCID"] if usb_ccid else 0
    usb_itf |= PHY_USB_ITF["WCID"] if usb_wcid else 0
    usb_itf |= PHY_USB_ITF["HID"] if usb_hid else 0
    usb_itf |= PHY_USB_ITF["KB"] if usb_kb else 0
    blob = phy_tlv(parsed_vid, parsed_pid, led_driver, led_pin, led_brightness, opts, up_btn, usb_product, curves, usb_itf)
    (BASE / "last-phy.bin").write_bytes(blob)
    log(f"generated PHY blob {blob.hex()}")
    return {"phy_hex": blob.hex(), "bytes": len(blob), "vid": f"{parsed_vid:04x}" if parsed_vid is not None else None, "pid": f"{parsed_pid:04x}" if parsed_pid is not None else None, "note": "PHY serialization matches pypicokey PhyData; direct write path pending exact PicoKeyApp protocol port"}


@app.post("/feature/{feature}")
def feature(feature: str) -> dict[str, Any]:
    return feature_stub(feature)
