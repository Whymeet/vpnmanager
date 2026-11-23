#!/bin/bash
# Установка kill switch для Claude в WSL.
#   sudo ./install.sh <IP-выхода-VPS> [ещё IP...]
# Повторный запуск обновляет файлы; без адресов настройки не меняются.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

[ "$(id -u)" -eq 0 ] || { echo "Запусти через sudo: sudo $0 <IP-выхода-VPS>" >&2; exit 1; }
systemctl is-system-running >/dev/null 2>&1 || [ "$(cat /proc/1/comm)" = systemd ] || {
  echo "В WSL выключен systemd: добавь в /etc/wsl.conf [boot] systemd=true и сделай wsl --shutdown." >&2; exit 1; }

if ! command -v nft >/dev/null; then
  echo "· ставлю nftables"
  apt-get install -y nftables >/dev/null
fi
command -v curl >/dev/null || apt-get install -y curl >/dev/null

echo "· файлы"
install -m 755 claude-killswitchd /usr/local/sbin/claude-killswitchd
install -m 755 claude-guard /usr/local/bin/claude-guard
install -m 644 claude-killswitch.service /etc/systemd/system/claude-killswitch.service
[ -f /etc/claude-killswitch.conf ] || install -m 644 claude-killswitch.conf /etc/claude-killswitch.conf
if [ $# -gt 0 ]; then
  sed -i "s|^ALLOWED_EXITS=.*|ALLOWED_EXITS=\"$*\"|" /etc/claude-killswitch.conf
fi

echo "· проверяю, что ядро принимает правила"
/usr/local/sbin/claude-killswitchd ruleset closed closed | nft -c -f - || {
  echo "nftables отказал — правила не поставлены." >&2; exit 1; }

echo "· функция claude → claude-guard"
snippet='# claude-killswitch begin
claude() { /usr/local/bin/claude-guard "$@"; }
# claude-killswitch end'
for rc in /etc/bash.bashrc /etc/zsh/zshrc; do
  [ -f "$rc" ] || continue
  sed -i '/# claude-killswitch begin/,/# claude-killswitch end/d' "$rc"
  printf '\n%s\n' "$snippet" >>"$rc"
done

echo "· служба"
systemctl daemon-reload
systemctl enable claude-killswitch >/dev/null 2>&1
systemctl restart claude-killswitch
sleep 8
claude-guard --status || true
echo
echo "Готово. Открой новый терминал: команда claude теперь идёт через проверку VPN."
grep -q '^ALLOWED_EXITS=""' /etc/claude-killswitch.conf && \
  echo "ВНИМАНИЕ: не задан IP выхода VPS — Claude закрыт всегда. sudo $0 <IP>"
exit 0
