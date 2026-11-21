#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTLIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check-only)
      CHECK_ONLY=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: adb-smoke.sh [--check-only]

Runs Tendril Android instrumentation smoke tests (TendrilAndroidSmokeTest)
against an attached arm64-v8a Android device or emulator via Gradle.

Environment overrides:
  ANDROID_HOME    Path to Android SDK (used to locate platform-tools/adb)
  ANDROID_SERIAL  Target device serial when multiple devices are attached
  GRADLE_BIN      Gradle executable (defaults to 'gradle' in PATH)
  JAVA_HOME       JDK 17 or 21 home for Gradle / AGP
EOF
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

ADB_BIN="${ADB_BIN:-$(command -v adb || true)}"
if [ -z "$ADB_BIN" ] && [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/platform-tools/adb" ]; then
  ADB_BIN="$ANDROID_HOME/platform-tools/adb"
fi

if [ -z "$ADB_BIN" ]; then
  printf 'adb not found in PATH or ANDROID_HOME/platform-tools.\n' >&2
  printf 'Install Android platform-tools or export ANDROID_HOME and retry.\n' >&2
  exit 1
fi

DEVICES_OUT="$("$ADB_BIN" devices -l)"
printf '%s\n' "$DEVICES_OUT"

READY_SERIALS=()
while IFS= read -r line; do
  case "$line" in
    ""|"List of devices attached"*)
      continue
      ;;
  esac
  serial="${line%%[[:space:]]*}"
  rest="${line#"$serial"}"
  state="$(printf '%s' "$rest" | awk '{print $1}')"
  if [ "$state" = "device" ]; then
    READY_SERIALS+=("$serial")
  fi
done <<< "$DEVICES_OUT"

if [ "${#READY_SERIALS[@]}" -eq 0 ]; then
  printf '\nNo authorized Android device or emulator attached.\n'
  printf 'Connect a USB-debugging-enabled arm64-v8a phone or start an emulator, then re-run:\n'
  printf '  %s\n' "$0"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    exit 0
  fi
  exit 3
fi

TARGET_SERIAL="${ANDROID_SERIAL:-${READY_SERIALS[0]}}"
SERIAL_READY=0
for serial in "${READY_SERIALS[@]}"; do
  if [ "$serial" = "$TARGET_SERIAL" ]; then
    SERIAL_READY=1
    break
  fi
done
if [ "$SERIAL_READY" -ne 1 ]; then
  printf 'Target device %s is not in ready state (ready: %s).\n' "$TARGET_SERIAL" "${READY_SERIALS[*]}" >&2
  exit 3
fi
ABI="$("$ADB_BIN" -s "$TARGET_SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r\n')"
printf 'Target device: %s (abi=%s)\n' "$TARGET_SERIAL" "$ABI"

if [ "$ABI" != "arm64-v8a" ]; then
  printf 'Warning: tendril-kotlin AAR packages arm64-v8a only (device abi=%s).\n' "$ABI" >&2
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  printf 'Check-only mode complete.\n'
  exit 0
fi

GRADLE_CMD="${GRADLE_BIN:-$(command -v gradle || true)}"
if [ -z "$GRADLE_CMD" ]; then
  printf 'gradle not found in PATH; set GRADLE_BIN to a Gradle 8.14+ executable.\n' >&2
  exit 1
fi

export ANDROID_SERIAL="$TARGET_SERIAL"
exec "$GRADLE_CMD" -p "$KOTLIN_DIR" --no-daemon -Dorg.gradle.jvmargs="-Xmx3g" connectedDebugAndroidTest
