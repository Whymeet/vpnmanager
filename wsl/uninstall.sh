#!/bin/bash
# Удаление kill switch для Claude из WSL: sudo ./uninstall.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Запусти через sudo: sudo $0" >&2; exit 1; }
systemctl disable --now claude-killswitch 2>/dev/null || true
/usr/local/sbin/claude-killswitchd remove 2>/dev/null || nft delete table inet claude_ks 2>/dev/null || true
for rc in /etc/bash.bashrc /etc/zsh/zshrc; do
  [ -f "$rc" ] && sed -i '/# claude-killswitch begin/,/# claude-killswitch end/d' "$rc"
done
rm -f /etc/systemd/system/claude-killswitch.service /usr/local/sbin/claude-killswitchd /usr/local/bin/claude-guard
systemctl daemon-reload
echo "Удалено. Настройки оставлены: /etc/claude-killswitch.conf"
