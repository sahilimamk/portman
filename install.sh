#!/usr/bin/env bash
# PortMan installer — copies the single-file app to ~/.local/bin
# and registers a "Port Manager" entry in the application menu.
set -e
cd "$(dirname "$0")"

install -Dm755 portman.py "$HOME/.local/bin/portman"

mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/portman.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Port Manager
Comment=Manage all ports — listening, connections, firewall, USB/serial
Exec=$HOME/.local/bin/portman
Icon=network-workgroup
Terminal=false
Categories=System;Network;Utility;
Keywords=port;ports;firewall;ufw;ss;tcp;udp;usb;serial;
EOF

echo "Installed. Run 'portman' or open 'Port Manager' from your app menu."
