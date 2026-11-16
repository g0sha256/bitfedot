#!/usr/bin/env bash
# Per-user install of BitFedot (no root). Uninstall with: ./install.sh --uninstall
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib="$HOME/.local/lib/bitfedot"
bin="$HOME/.local/bin/bitfedot"
apps="$HOME/.local/share/applications"
icons="$HOME/.local/share/icons/hicolor"
id=io.github.g0sha256.BitFedot

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -rf "$lib" "$bin" "$apps/$id.desktop" \
        "$icons/scalable/apps/$id.svg" "$icons/symbolic/apps/$id-symbolic.svg"
    echo "Removed the app. Node services and data are untouched — remove those from"
    echo "Settings → Remove services before uninstalling, and delete the data folder yourself."
    exit 0
fi

missing=()
python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1"); from gi.repository import Gtk, Adw' 2>/dev/null \
    || missing+=(python3-gobject gobject-introspection gtk4 libadwaita)
for b in curl gpg; do command -v "$b" >/dev/null || missing+=("$b"); done
if ((${#missing[@]})); then
    echo "Missing dependencies. Install them with:"
    echo "    sudo dnf install ${missing[*]/gpg/gnupg2}"
    exit 1
fi

# files installed under an earlier application ID
for old in io.github.bitfedot.BitFedot; do
    rm -f "$apps/$old.desktop" "$icons/scalable/apps/$old.svg" "$icons/symbolic/apps/$old-symbolic.svg"
done
rm -rf "$lib"
mkdir -p "$lib" "$(dirname "$bin")" "$apps" "$icons/scalable/apps" "$icons/symbolic/apps"
cp -r "$here/bitfedot" "$lib/"
find "$lib" -name __pycache__ -prune -exec rm -rf {} +
cat > "$bin" <<LAUNCH
#!/bin/sh
PYTHONPATH="$lib\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m bitfedot "\$@"
LAUNCH
chmod +x "$bin"
sed "s|^Exec=bitfedot|Exec=$bin|" "$here/bitfedot/data/$id.desktop" > "$apps/$id.desktop"
cp "$here/bitfedot/data/icons/hicolor/scalable/apps/$id.svg" "$icons/scalable/apps/"
cp "$here/bitfedot/data/icons/hicolor/symbolic/apps/$id-symbolic.svg" "$icons/symbolic/apps/"
gtk4-update-icon-cache -q -t "$icons" 2>/dev/null || true
update-desktop-database -q "$apps" 2>/dev/null || true
echo "Installed. Launch “BitFedot” from the app grid, or run: $bin"
if [[ -f "$HOME/.config/nodestead/settings.json" ]]; then
    echo "An earlier Nodestead installation was found: BitFedot will offer to take it over on first start."
fi
