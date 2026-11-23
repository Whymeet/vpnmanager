#!/bin/bash
# Установка kill switch для Claude в WSL.
#   sudo ./install.sh <IP-выхода-VPS> [ещё IP...]
# Повторный запуск обновляет файлы; без адресов настройки не меняются.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

[ "$(id -u)" -eq 0 ] || { echo "Запусти через sudo: sudo $0 <IP-выхода-VPS>" >&2; exit 1; }
systemctl is-system-running >/dev/null 2>&1 || [ "$(cat /proc/1/comm)" = systemd ] || {
  echo "В WSL выключен systemd: добавь в /etc/wsl.conf [boot] systemd=true и сделай wsl --shutdown." >&2; exit 1; }

# Пакеты: сначала обычные источники с коротким ожиданием, не вышло — зеркало
# (archive.ubuntu.com через некоторые VPN не отвечает, и apt висит без конца).
MIRROR="${MIRROR:-http://mirror.yandex.ru/ubuntu/}"
APT_OPTS=(-y -q -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=1)
# Обычный источник отвечает за 8 с? Иначе apt висит минутами — сразу зеркало.
archive_ok() {
  local u
  u=$(grep -rhoE '^(deb|URIs:) +https?://[^ ]+' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
      | grep -oE 'https?://[^ ]+' | grep -v launchpad | head -1)
  [ -n "$u" ] && curl -fsS -o /dev/null -m 8 "${u%/}/dists/$(. /etc/os-release && echo "$VERSION_CODENAME")/Release"
}
# Без терминала и вопросов: под timeout apt, который тронет терминал
# (debconf, dpkg), ядро останавливает (SIGTTOU) — установка «висит».
export DEBIAN_FRONTEND=noninteractive
apt_install() {
  if archive_ok && timeout --foreground 120 apt-get install "${APT_OPTS[@]}" "$@" </dev/null >/dev/null 2>&1; then return 0; fi
  echo "  обычный источник пакетов не отвечает — беру зеркало $MIRROR"
  local list codename
  codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
  list=$(mktemp)
  printf 'deb %s %s main universe\ndeb %s %s-updates main universe\ndeb %s %s-security main universe\n' \
    "$MIRROR" "$codename" "$MIRROR" "$codename" "$MIRROR" "$codename" >"$list"
  local src=(-o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=-)
  timeout --foreground 180 apt-get update "${APT_OPTS[@]}" "${src[@]}" </dev/null >/dev/null 2>&1 || true
  local rc=0
  timeout --foreground 180 apt-get install "${APT_OPTS[@]}" "${src[@]}" "$@" </dev/null >/dev/null || rc=$?
  rm -f "$list"
  return $rc
}

if ! command -v nft >/dev/null; then
  echo "· ставлю nftables"
  apt_install nftables || { echo "Не удалось поставить nftables — проверь интернет и запусти ещё раз." >&2; exit 1; }
fi
command -v curl >/dev/null || apt_install curl

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
