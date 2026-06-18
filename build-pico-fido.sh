#!/usr/bin/env bash
#
# build-pico-fido.sh — Reproduce the pico-fido FIDO2 image PicoKeyApp flashes.
#
# Source project: https://github.com/polhenarejos/pico-fido  (FIDO2/U2F)
# SDK/crypto:     https://github.com/polhenarejos/pico-keys-sdk (mbedtls fork)
#
# The image the app downloads is NOT the stock GitHub release. It is a custom
# build with extra crypto enabled in the mbedtls config:
#     MBEDTLS_EDDSA_C  -> Ed25519 / EdDSA  (FIDO2_ALG_EDDSA, FIDO2_ALG_ED25519)
#     MBEDTLS_SHA3_C   -> HMAC-SHA3-224/256/384/512
# Stock pico-keys-sdk leaves both undefined; this script patches them ON.
#
# Reproducibility:
#   --feature parity gets you a FUNCTIONALLY identical binary (same algorithms,
#   same size class). BYTE-identical also needs the build path to match, because
#   assert()/__FILE__ bakes the author's absolute path into the image:
#       /Users/trocotronic/Devel/pico/pico-fido2/pico-fido
#   --prefix-map rewrites our build path to that string via -ffile-prefix-map so
#   the embedded path strings match. Even then, exact toolchain version, mbedtls
#   commit and build timestamps can still differ a few bytes — true bit-for-bit
#   repro is not guaranteed without the author's exact environment.
#
# Usage:
#   ./build-pico-fido.sh --board pico2 [options]
#
# Options:
#   --board    <name>    pico-sdk board id          (default: pico2)
#   --platform <id>      rp2040|rp2350|esp32s2|esp32s3 (default: from board)
#   --vidpid   <preset>  USB VID/PID preset          (default: Pico)
#   --version  <ref>     git tag/branch/commit        (default: v7.6; latest upstream tag)
#   --fw-version <x.y>   override advertised firmware version (e.g. 7.7)
#   --features <list>    comma crypto to force-enable (default: eddsa,sha3)
#                        known: eddsa,sha3  ('' = stock config, no patch)
#   --prefix-map         remap build path to the author's path for byte parity
#   --workdir  <dir>     clone/build root            (default: ./pico-fido-build)
#   --jobs     <n>       parallel jobs               (default: nproc)
#   --clean              wipe build dir first
#   --verify             after build, string-diff vs the captured image
#                        ($HOME/pico-capture/*.uf2)
#   --flash              update device non-interactively (skip the prompt)
#   --no-flash           never update; suppress the prompt (for scripts/CI)
#   --erase              FULL chip-erase BEFORE flashing = factory reset.
#                        WIPES credentials / PIN / counters. Destructive.
#                        Requires typing ERASE to confirm (or in a prompt).
#   --image <path>       use this uf2 instead of building (implies --no-build)
#                        e.g. the captured app image
#   --no-build           skip compile; use existing dist/captured image
#
#   If neither --flash nor --no-flash is given and you run in a terminal, the
#   script ASKS at the end whether to update the device (default: No).
#   -h | --help
#
# ---------------------------------------------------------------------------
# DATA-PRESERVING UPDATE (same as the app):
#   pico-fido stores credentials / PIN / counters in a SEPARATE high flash
#   region. The firmware .uf2 only contains the program region
#   (~0x10000000..0x1006fc00). Flashing writes ONLY the sectors present in the
#   uf2 (BOOTSEL/picotool erase-on-write per 4 KB sector); the data region is
#   never touched -> credentials survive the update.
#
#   This script flashes with `picotool load` (program + verify, NO full erase).
#   What DESTROYS data: a full chip-erase (`picotool erase`) or flashing the
#   pico_nuke image. This script never does either.
# ---------------------------------------------------------------------------
#
# Output: <workdir>/dist/pico_fido_<board>_<version>.uf2|.bin
#
set -euo pipefail

REPO="https://github.com/polhenarejos/pico-fido"
SDK_REPO="https://github.com/raspberrypi/pico-sdk"
BOARD="pico2"; PLATFORM=""; VIDPID="Pico"; VERSION="v7.6"; FW_VERSION=""
FEATURES="eddsa,sha3"; PREFIX_MAP=0; CLEAN=0; VERIFY=0
FLASH=0; NOFLASH=0; NOBUILD=0; IMAGE=""; ERASE=0
WORKDIR="$(pwd)/pico-fido-build"
AUTHOR_PATH="/Users/trocotronic/Devel/pico/pico-fido2/pico-fido"
if command -v nproc >/dev/null 2>&1; then JOBS="$(nproc)"; else JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"; fi

while [ $# -gt 0 ]; do
  case "$1" in
    --board)    BOARD="$2"; shift 2;;
    --platform) PLATFORM="$2"; shift 2;;
    --vidpid)   VIDPID="$2"; shift 2;;
    --version)  VERSION="$2"; shift 2;;
    --fw-version) FW_VERSION="$2"; shift 2;;
    --features) FEATURES="$2"; shift 2;;
    --prefix-map) PREFIX_MAP=1; shift;;
    --workdir)  WORKDIR="$2"; shift 2;;
    --jobs)     JOBS="$2"; shift 2;;
    --clean)    CLEAN=1; shift;;
    --verify)   VERIFY=1; shift;;
    --flash)    FLASH=1; shift;;
    --no-flash) NOFLASH=1; shift;;
    --erase)    ERASE=1; shift;;
    --image)    IMAGE="$2"; NOBUILD=1; shift 2;;
    --no-build) NOBUILD=1; shift;;
    -h|--help)  grep '^#' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

BUILD_BOARD="$BOARD"

if [ -z "$PLATFORM" ]; then
  case "$BUILD_BOARD" in
    tenstar|pico2*|*rp2350*) PLATFORM="rp2350";; pico*|*rp2040*) PLATFORM="rp2040";;
    *esp32s3*) PLATFORM="esp32s3";; *esp32s2*) PLATFORM="esp32s2";; *) PLATFORM="rp2350";;
  esac
fi

log() { printf '\033[1;32m[build]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

fw_hex() {
  case "$1" in
    [0-9]*.[0-9]*)
      local major="${1%%.*}" minor="${1#*.}"
      printf '0x%02X%02X' "$major" "$minor"
      ;;
    *) die "invalid --fw-version '$1' (expected x.y, e.g. 7.7)";;
  esac
}

install_tenstar_board() {
  local board_dir="$PICO_SDK_PATH/src/boards/include/boards"
  [ -d "$board_dir" ] || die "pico-sdk boards dir not found: $board_dir"
  cat > "$board_dir/tenstar.h" <<'EOF'
/* Generated by build-pico-fido.sh from PicoKeyApp pico_boards_manifest.json. */

#ifndef _BOARDS_TENSTAR_H
#define _BOARDS_TENSTAR_H

pico_board_cmake_set(PICO_PLATFORM, rp2350)

#define TENSTAR
#define PICO_RP2350A 1

#ifndef PICO_DEFAULT_UART
#define PICO_DEFAULT_UART 0
#endif
#ifndef PICO_DEFAULT_UART_TX_PIN
#define PICO_DEFAULT_UART_TX_PIN 0
#endif
#ifndef PICO_DEFAULT_UART_RX_PIN
#define PICO_DEFAULT_UART_RX_PIN 1
#endif

#ifndef PICO_DEFAULT_WS2812_PIN
#define PICO_DEFAULT_WS2812_PIN 22
#endif

#ifndef PICO_DEFAULT_I2C
#define PICO_DEFAULT_I2C 1
#endif
#ifndef PICO_DEFAULT_I2C_SDA_PIN
#define PICO_DEFAULT_I2C_SDA_PIN 6
#endif
#ifndef PICO_DEFAULT_I2C_SCL_PIN
#define PICO_DEFAULT_I2C_SCL_PIN 7
#endif

#ifndef PICO_DEFAULT_SPI
#define PICO_DEFAULT_SPI 0
#endif
#ifndef PICO_DEFAULT_SPI_SCK_PIN
#define PICO_DEFAULT_SPI_SCK_PIN 18
#endif
#ifndef PICO_DEFAULT_SPI_TX_PIN
#define PICO_DEFAULT_SPI_TX_PIN 19
#endif
#ifndef PICO_DEFAULT_SPI_RX_PIN
#define PICO_DEFAULT_SPI_RX_PIN 16
#endif
#ifndef PICO_DEFAULT_SPI_CSN_PIN
#define PICO_DEFAULT_SPI_CSN_PIN 17
#endif

#define PICO_BOOT_STAGE2_CHOOSE_W25Q080 1

#ifndef PICO_FLASH_SPI_CLKDIV
#define PICO_FLASH_SPI_CLKDIV 2
#endif

pico_board_cmake_set_default(PICO_FLASH_SIZE_BYTES, (16 * 1024 * 1024))
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (16 * 1024 * 1024)
#endif

pico_board_cmake_set_default(PICO_RP2350_A2_SUPPORTED, 1)
#ifndef PICO_RP2350_A2_SUPPORTED
#define PICO_RP2350_A2_SUPPORTED 1
#endif

#endif
EOF
}

mkdir -p "$WORKDIR"; cd "$WORKDIR"

if [ "$NOBUILD" = 1 ]; then
  # ---- skip compile: resolve an existing image to flash ---------------------
  if [ -n "$IMAGE" ]; then OUT="$IMAGE"; else OUT="$(ls -1t "$WORKDIR"/dist/*.uf2 2>/dev/null | head -1)"; fi
  [ -n "${OUT:-}" ] && [ -f "$OUT" ] || die "no image to flash (use --image <uf2> or build first)"
  log "Flash image: $OUT"
else
# ---- fetch source -----------------------------------------------------------
if [ ! -d pico-fido/.git ]; then
  log "Cloning pico-fido"; git clone --recurse-submodules "$REPO" pico-fido
fi
cd pico-fido
log "Checkout $VERSION"
git fetch --tags --quiet || true
git checkout --quiet "$VERSION"
git submodule update --init --recursive

if [ -n "$FW_VERSION" ]; then
  VHEX="$(fw_hex "$FW_VERSION")"
  log "Patching src/fido/version.h -> $FW_VERSION ($VHEX)"
  perl -0pi -e "s/#define PICO_FIDO_VERSION 0x[0-9A-Fa-f]{4}/#define PICO_FIDO_VERSION $VHEX/" src/fido/version.h
fi

# ---- patch mbedtls config for feature parity --------------------------------
MBCFG="pico-keys-sdk/config/mbedtls_config.h"
[ -f "$MBCFG" ] || MBCFG="$(find . -path '*pico-keys-sdk*mbedtls_config.h' | head -1)"
patch_def() {  # $1 = MBEDTLS macro
  grep -qE "^[[:space:]]*#define[[:space:]]+$1\b" "$MBCFG" && { log "  $1 already defined"; return; }
  printf '\n#define %s   /* enabled by build-pico-fido.sh feature parity */\n' "$1" >> "$MBCFG"
  log "  + $1"
}
if [ -n "$FEATURES" ] && [ -f "$MBCFG" ]; then
  log "Patching $MBCFG (features: $FEATURES)"
  ENABLE_EDDSA=0
  IFS=',' read -ra FL <<< "$FEATURES"
  for f in "${FL[@]}"; do case "$f" in
    eddsa) ENABLE_EDDSA=1; log "  EdDSA handled by CMake ENABLE_EDDSA=1";;
    sha3)  patch_def MBEDTLS_SHA3_C;;
    *) die "unknown feature: $f";;
  esac; done
elif [ -n "$FEATURES" ]; then
  die "mbedtls_config.h not found; cannot apply features"
fi

case ",${FEATURES}," in
  *,eddsa,*) CMAKE_EDDSA="-DENABLE_EDDSA=1";;
  *) CMAKE_EDDSA="";;
esac

DIST="$WORKDIR/dist"; mkdir -p "$DIST"
OUT_VERSION="$VERSION"
[ -n "$FW_VERSION" ] && OUT_VERSION="v$FW_VERSION"
EXTRA_C=""
[ "$PREFIX_MAP" = 1 ] && EXTRA_C="-ffile-prefix-map=$WORKDIR/pico-fido=$AUTHOR_PATH"

# =============================================================================
case "$PLATFORM" in
  rp2040|rp2350)
    command -v cmake >/dev/null || die "cmake missing (brew install cmake)"
    command -v arm-none-eabi-gcc >/dev/null || die "ARM gcc missing (brew install --cask gcc-arm-embedded)"
    export PICO_SDK_PATH="${PICO_SDK_PATH:-$WORKDIR/pico-sdk}"
    if [ ! -d "$PICO_SDK_PATH/.git" ]; then
      log "Cloning pico-sdk -> $PICO_SDK_PATH"
      git clone --branch master --recurse-submodules "$SDK_REPO" "$PICO_SDK_PATH"
    fi
    [ "$BUILD_BOARD" = "tenstar" ] && { log "Installing tenstar board (rp2350, 16MB, WS2812 pin 22)"; install_tenstar_board; }
    BUILD="build-$BOARD"; [ "$CLEAN" = 1 ] && rm -rf "$BUILD"; mkdir -p "$BUILD"; cd "$BUILD"
    log "cmake (board=$BUILD_BOARD platform=$PLATFORM vidpid=$VIDPID prefix-map=$PREFIX_MAP)"
    cmake .. -DCMAKE_BUILD_TYPE=Release \
      -DPICO_BOARD="$BUILD_BOARD" -DPICO_PLATFORM="$PLATFORM" -DVIDPID="$VIDPID" \
      ${CMAKE_EDDSA:+$CMAKE_EDDSA} \
      ${EXTRA_C:+-DCMAKE_C_FLAGS="$EXTRA_C" -DCMAKE_CXX_FLAGS="$EXTRA_C"}
    log "make -j$JOBS"; make -j"$JOBS"
    UF2="$(ls -1 *.uf2 2>/dev/null | head -1)"; [ -n "$UF2" ] || die "no .uf2 produced"
    OUT="$DIST/pico_fido_${BOARD}_${OUT_VERSION}.uf2"; cp "$UF2" "$OUT"
    ;;
  esp32s2|esp32s3)
    [ -n "${IDF_PATH:-}" ] || die "esp-idf not active (. \$IDF_PATH/export.sh)"
    command -v idf.py >/dev/null || die "idf.py not on PATH"
    idf.py set-target "$PLATFORM"; [ "$CLEAN" = 1 ] && idf.py fullclean
    idf.py -DVIDPID="$VIDPID" build
    BIN="$(ls -1 build/*.bin 2>/dev/null | grep -iE 'fido' | head -1 || ls -1 build/*.bin | head -1)"
    [ -n "$BIN" ] || die "no .bin produced"
    OUT="$DIST/pico_fido_${BOARD}_${OUT_VERSION}.bin"; cp "$BIN" "$OUT"
    ;;
  *) die "unknown platform: $PLATFORM";;
esac
log "Image: $OUT  ($(stat -f%z "$OUT" 2>/dev/null || stat -c%s "$OUT") bytes)"
fi   # end build / no-build

# ---- verify vs captured image ----------------------------------------------
if [ "$VERIFY" = 1 ]; then
  CAP="$(ls -1 "$HOME"/pico-capture/*.uf2 2>/dev/null | head -1)"
  [ -n "$CAP" ] || { log "verify: no captured image in ~/pico-capture"; exit 0; }
  log "Verify built vs captured: $(basename "$CAP")"
  python3 - "$OUT" "$CAP" <<'PY'
import sys,struct,re
def strs(fn):
    d=open(fn,'rb').read(); seg={}
    for i in range(len(d)//512):
        b=d[i*512:(i+1)*512]
        if struct.unpack('<I',b[0:4])[0]!=0x0A324655: continue
        a,p=struct.unpack('<II',b[12:20]); seg[a]=b[32:32+p]
    raw=b"".join(seg[k] for k in sorted(seg))
    return raw, set(m.group().decode('latin1') for m in re.finditer(rb"[ -~]{5,}",raw))
rb,sb=strs(sys.argv[1]); rc,sc=strs(sys.argv[2])
feats=["FIDO2_ALG_EDDSA","ed25519","SigEd25519","HMAC-SHA3-256","hmacSHA3-512"]
print("  feature parity (present in BUILT / present in CAPTURED):")
for f in feats:
    print("   %-18s built=%s captured=%s"%(f, any(f in x for x in sb), any(f in x for x in sc)))
print("  payload bytes  built=%d captured=%d"%(len(rb),len(rc)))
print("  byte-identical:" , rb==rc)
print("  shared strings=%d  built-only=%d  captured-only=%d"%(len(sb&sc),len(sb-sc),len(sc-sb)))
PY
fi

# ---- decide whether to update (optional + interactive) ---------------------
if [ "$NOFLASH" = 1 ]; then
  FLASH=0
elif [ "$FLASH" != 1 ]; then
  if [ -t 0 ]; then
    printf '\033[1;36m\nUpdate the connected device now with this image? [y/N]: \033[0m'
    read -r ans
    case "$ans" in
      [yYsS]*)
        FLASH=1
        if [ "$ERASE" = 0 ]; then
          printf '\033[1;36mErase ALL data first (factory reset, wipes credentials)? [y/N]: \033[0m'
          read -r ea; case "$ea" in [yYsS]*) ERASE=1;; esac
        fi;;
      *) FLASH=0; log "Skipping device update.";;
    esac
  else
    FLASH=0   # non-interactive and not forced -> never flash
  fi
fi

# ---- data-preserving device update -----------------------------------------
if [ "$FLASH" = 1 ]; then
  case "$PLATFORM" in
    esp32s2|esp32s3) die "ESP32 flashing not handled here; use: idf.py flash (data preserved unless you erase_flash)";;
  esac
  command -v picotool >/dev/null || die "picotool missing (brew install picotool)"
  [ "${OUT##*.}" = "uf2" ] || die "flash expects a .uf2 image, got: $OUT"

  printf '\033[1;33m
  ==== UPDATE (data-preserving) ====
  Image : %s
  Method: picotool load  (programs ONLY the uf2 sectors + verify, NO chip erase)
  Effect: firmware replaced; credentials / PIN / counters in the data region
          are NOT erased — same as the app'\''s Upgrade.
  NEVER run `picotool erase` or flash pico_nuke if you want to keep data.
\033[0m\n' "$OUT"

  # 1) put device in BOOTSEL without wiping. Try USB-triggered reboot first.
  if picotool info >/dev/null 2>&1; then
    log "Device reachable -> reboot to BOOTSEL (picotool reboot -f -u)"
    picotool reboot -f -u || true
  else
    printf '\033[1;33m  Device not in BOOTSEL. Enter bootloader now:\n'
    printf '    hold BOOTSEL button while plugging the board (or send the\n'
    printf '    app'\''s reboot-to-bootloader), then press ENTER.\033[0m\n'
    read -r _
  fi

  # 2) wait for BOOTSEL (picoboot) to enumerate
  log "Waiting for BOOTSEL device..."
  for _ in $(seq 1 60); do picotool info >/dev/null 2>&1 && break; sleep 0.5; done
  picotool info >/dev/null 2>&1 || die "no BOOTSEL device detected (timeout)"

  # 3) optional full chip-erase (DESTRUCTIVE: wipes credentials -> factory reset)
  if [ "$ERASE" = 1 ]; then
    printf '\033[1;31m
  !!! FULL CHIP ERASE requested — this WIPES all credentials / PIN / counters.
      This is irreversible (factory reset). Type ERASE to confirm: \033[0m'
    read -r confirm
    [ "$confirm" = "ERASE" ] || die "erase not confirmed; aborting before any write"
    log "picotool erase (whole flash)"
    picotool erase
  fi

  # 4) program + verify + run.
  #    without --erase: load writes only image sectors -> data survives.
  #    with --erase: flash was wiped -> clean install.
  log "picotool load (program + verify)"
  picotool load -v -x "$OUT"
  if [ "$ERASE" = 1 ]; then
    log "Flashed after erase. Device factory-reset to fresh firmware."
  else
    log "Flashed. Device rebooting into updated firmware; data preserved."
  fi
fi

log "Done."
