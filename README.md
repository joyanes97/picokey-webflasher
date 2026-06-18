# picokey-webflasher

Web flasher and manager for PicoKey-style firmware.

Features:

- Build Pico FIDO UF2 images from web UI.
- Upload and select existing UF2 images.
- Upgrade firmware without erasing data.
- Erase full flash and install clean firmware.
- Board selection from PicoKeyApp board manifest, with Tenstar defaults.
- Generate PHY commission blob for LED/product settings.
- PicoForge-style web UI without license checks.

Default target: Tenstar RP2350, 16MB flash, WS2812 LED on GPIO 22.

Run locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install fastapi uvicorn python-multipart pypicoboot
uvicorn app:app --host 0.0.0.0 --port 8080
```

Deploy on `dev-picokey`:

```bash
sudo ./deploy.sh
```

The server uses a GitHub deploy key at `~/.ssh/picokey-webflasher_deploy`.

Environment:

- `PICOKEY_DATA`: state directory, default `/opt/picokey-web/data`
- `PICOKEY_IMAGES`: UF2 image store, default `/opt/picokey-web/images`
- `PICOKEY_MANIFEST`: board manifest JSON path
- `PICOKEY_BUILD_SCRIPT`: build script path, default `/opt/picokey-web/build-pico-fido.sh`
- `PICOKEY_BUILD_ROOT`: build workdir, default `/opt/picokey-web/build`
