#!/usr/bin/env bash
# Build an AppImage from a Flutter Linux release bundle — a single self-contained
# file that runs on any desktop distro with NO apt/dpkg install: the user makes
# it executable and double-clicks it. Unlike a Flatpak, an AppImage is just a
# mounted image with FULL host access, so Dreamnail's system-proxy changes and
# its root stealth helper (pkexec) keep working exactly as they do from the .deb.
#
#   make_linux_appimage.sh <bundle-dir> <version> <output.AppImage> [icon.png] [icon.svg]
#
# AppDir layout (AppImage convention):
#   AppRun                                     -> execs usr/bin/dreamnail_ui
#   weather.desktop + weather.png              top-level (required by the tool)
#   usr/bin/                                   the whole Flutter bundle, incl.
#                                              lib/libdreamnail_ffi.so, the sibling
#                                              `xray`, and `dreamnail-tunhelper`
#   usr/share/applications/weather.desktop
#   usr/share/icons/hicolor/{512x512,scalable}/apps/weather.{png,svg}
#
# appimagetool is fetched on demand (not preinstalled on the CI runner) and run
# with --appimage-extract-and-run so no FUSE is needed at BUILD time. Point
# $APPIMAGETOOL at a local binary to skip the download.
set -euo pipefail

bundle="$1"; version="$2"; out="$3"
icon_png="${4:-}"; icon_svg="${5:-}"
[ -x "$bundle/dreamnail_ui" ] || { echo "no dreamnail_ui in $bundle" >&2; exit 1; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
appdir="$work/AppDir"
install -d "$appdir/usr/bin" \
           "$appdir/usr/share/applications" \
           "$appdir/usr/share/icons/hicolor/512x512/apps" \
           "$appdir/usr/share/icons/hicolor/scalable/apps"

# The whole bundle -> usr/bin. dreamnail_ui's rpath is $ORIGIN/lib, so lib lands
# at usr/bin/lib and resolves; the engine finds `xray`/`dreamnail-tunhelper` as
# current_exe() siblings, also in usr/bin.
cp -a "$bundle/." "$appdir/usr/bin/"
chmod 0755 "$appdir/usr/bin/dreamnail_ui"

# Icon named 'weather' (matches the Icon= key). appimagetool needs a copy at the
# AppDir root too.
if [ -n "$icon_png" ] && [ -f "$icon_png" ]; then
  cp "$icon_png" "$appdir/usr/share/icons/hicolor/512x512/apps/weather.png"
  cp "$icon_png" "$appdir/weather.png"
fi
[ -n "$icon_svg" ] && [ -f "$icon_svg" ] && \
  cp "$icon_svg" "$appdir/usr/share/icons/hicolor/scalable/apps/weather.svg"

# .desktop — mirrors the .deb's entry. Lives both at the AppDir root (tool
# requirement) and under usr/share/applications (convention).
cat > "$appdir/weather.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Weather
GenericName=Weather
Comment=Weather and forecasts
Exec=dreamnail_ui
Icon=weather
Terminal=false
Categories=Utility;
StartupWMClass=com.dreamnail.dreamnail_ui
EOF
cp "$appdir/weather.desktop" "$appdir/usr/share/applications/weather.desktop"

# Bundle the tray + hotkey libraries that are NOT installed by default on many
# desktops (Fedora, Arch, openSUSE: keybinder + ayatana are extras), so a
# double-click doesn't silently die with a loader error. GTK/glib themselves
# stay the system's. Copied from the build box (ubuntu-22.04 has them as
# build deps), resolved through symlinks.
extra="$appdir/usr/lib/dreamnail-extra"; install -d "$extra"
for so in libkeybinder-3.0.so.0 libayatana-appindicator3.so.1 libayatana-indicator3.so.7 \
          libayatana-ido3-0.4.so.0 libdbusmenu-glib.so.4 libdbusmenu-gtk3.so.4; do
  src="$(ldconfig -p 2>/dev/null | awk -v n="$so" '$1==n {print $NF; exit}')"
  if [ -n "$src" ] && [ -e "$src" ]; then cp -L "$src" "$extra/$so"; else echo "note: $so not on build box, not bundled" >&2; fi
done

# AppRun: resolve our own directory and exec the app binary (no FUSE assumptions;
# the AppImage runtime has already mounted us at $APPDIR). Before starting, check
# every library still resolves; if one doesn't, SAY so in a window (a missing
# library used to make the double-click do nothing at all).
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export APPDIR="${APPDIR:-$HERE}"
export LD_LIBRARY_PATH="$HERE/usr/lib/dreamnail-extra${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# Check with the bundled lib dir on the path too (plugin .so files carry a CI
# RUNPATH, so standalone they "can't find" libflutter_linux_gtk.so). grep+sed,
# not awk: minimal distros (Tumbleweed) ship without awk. Anything we bundle
# ourselves is never reported — a false alarm here would block a working app.
missing=""
for so in $(LD_LIBRARY_PATH="$HERE/usr/bin/lib:$LD_LIBRARY_PATH" ldd "$HERE/usr/bin/dreamnail_ui" "$HERE"/usr/bin/lib/*.so 2>/dev/null | grep 'not found' | sed 's/^[[:space:]]*//; s/[[:space:]].*//' | sort -u); do
  [ -e "$HERE/usr/bin/lib/$so" ] || [ -e "$HERE/usr/lib/dreamnail-extra/$so" ] || missing="$missing$so "
done
if [ -n "$missing" ]; then
  id="$(. /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}")"
  case "$id" in
    *fedora*|*rhel*) hint="sudo dnf install gtk3" ;;
    *arch*)          hint="sudo pacman -S gtk3" ;;
    *suse*)          hint="sudo zypper install libgtk-3-0" ;;
    *debian*|*ubuntu*) hint="sudo apt install libgtk-3-0" ;;
    *) hint="install GTK 3 from your package manager" ;;
  esac
  msg="Weather can't start: missing system libraries: $missing
Fix: $hint  — then open Weather again."
  echo "$msg" >&2
  if command -v zenity >/dev/null 2>&1; then zenity --error --title=Weather --text="$msg" 2>/dev/null
  elif command -v kdialog >/dev/null 2>&1; then kdialog --title Weather --error "$msg" 2>/dev/null
  elif command -v notify-send >/dev/null 2>&1; then notify-send Weather "$msg" 2>/dev/null
  elif command -v xmessage >/dev/null 2>&1; then xmessage "$msg"
  fi
  exit 1
fi
exec "$HERE/usr/bin/dreamnail_ui" "$@"
EOF
chmod 0755 "$appdir/AppRun"

# Locate (or fetch) appimagetool.
tool="${APPIMAGETOOL:-}"
if [ -z "$tool" ]; then
  tool="$work/appimagetool"
  url="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  echo "fetching appimagetool…" >&2
  curl -fsSL "$url" -o "$tool"
  chmod +x "$tool"
fi

rm -f "$out"
# --appimage-extract-and-run: run the tool without needing FUSE on the builder.
ARCH=x86_64 "$tool" --appimage-extract-and-run "$appdir" "$out"
echo "appimage: $out ($(du -h "$out" | cut -f1))"
