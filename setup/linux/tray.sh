#!/bin/bash
# Значок службы рядом с часами: шаг установки (install.sh). Идёт от имени человека в
# его сеансе и пишет, что вышло:
#
#   tray.sh <путь к установленному vpnlock>
#
# Значку нужна область значков рабочего стола. На чистом GNOME её нет: скрипт ставит
# расширение AppIndicator и включает его. Защита от значка не зависит, поэтому шаг
# никогда не прерывает установку: не вышло — называет причину и завершается с кодом 0.
# Автозапуск ставит сам vpnlock (/etc/xdg/autostart), здесь значок запускается сразу.
set -uo pipefail

VPNLOCK="${1:-/opt/vpnlock/bin/vpnlock}"
PACKAGE="gnome-shell-extension-appindicator"

step() { printf '· %s\n' "$*"; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf '✗ %s\n' "$*"; }

# Есть ли на шине область значков.
has_host() {
  gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner org.kde.StatusNotifierWatcher 2>/dev/null | grep -q true
}

install_package() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo -p '  Пароль: ' apt-get install -y "$PACKAGE"
  elif command -v dnf >/dev/null 2>&1; then
    sudo -p '  Пароль: ' dnf install -y "$PACKAGE"
  elif command -v pacman >/dev/null 2>&1; then
    sudo -p '  Пароль: ' pacman -S --noconfirm "$PACKAGE"
  elif command -v zypper >/dev/null 2>&1; then
    sudo -p '  Пароль: ' zypper --non-interactive install "$PACKAGE"
  else
    printf 'Не нашёл менеджер пакетов: нет apt-get, dnf, pacman и zypper.\n'
    return 1
  fi
}

# UUID расширения — по папке на диске, а не по названию системы: у одного и того же
# пакета он разный (Ubuntu и Debian — ubuntu-appindicators@ubuntu.com, Fedora —
# appindicatorsupport@rgcjonas.gmail.com).
extension_uuid() {
  local dirs dir uuid
  IFS=: read -r -a dirs <<<"${XDG_DATA_HOME:-$HOME/.local/share}:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
  for uuid in ubuntu-appindicators@ubuntu.com appindicatorsupport@rgcjonas.gmail.com; do
    for dir in "${dirs[@]}"; do
      if [ -d "$dir/gnome-shell/extensions/$uuid" ]; then
        printf '%s\n' "$uuid"
        return 0
      fi
    done
  done
  return 1
}

# gnome-extensions enable только дописывает UUID в настройку и отвечает 0, даже если
# такого расширения нет (проверено на GNOME 46). Той же записью обходимся, если команды
# нет или она отказала. Только что поставленное расширение работающий Shell ещё не
# знает: настройку он прочтёт при следующем входе.
enable_extension() {
  local uuid="$1" list
  gnome-extensions enable "$uuid" >/dev/null 2>&1 && return 0
  list="$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null)" || return 1
  case "$list" in
    *"'$uuid'"*) return 0 ;;
    "[]" | "@as []") list="['$uuid']" ;;
    *) list="${list%]}, '$uuid']" ;;
  esac
  gsettings set org.gnome.shell enabled-extensions "$list" 2>/dev/null
}

# Расширение, которое Shell уже знает, он поднимает сам, примерно за секунду.
host_appears() {
  local i
  for i in 1 2 3; do
    has_host && return 0
    sleep 1
  done
  return 1
}

setup_gnome() {
  local uuid
  if ! uuid="$(extension_uuid)"; then
    step "На этом GNOME нет области значков — ставлю пакет $PACKAGE"
    if ! install_package; then
      warn "Расширение не поставилось, причина выше. Значка не будет, защита работает. Поставь пакет $PACKAGE сам и войди в систему заново."
      return 0
    fi
    if ! uuid="$(extension_uuid)"; then
      warn "После установки пакета $PACKAGE расширения нет на диске. Значка не будет, защита работает."
      return 0
    fi
  fi
  if ! enable_extension "$uuid"; then
    warn "Не удалось включить расширение $uuid. Значка не будет, защита работает. Включи его в приложении «Расширения»."
    return 0
  fi
  if host_appears; then
    ok "Расширение $uuid включено"
  else
    ok "Расширение $uuid включено. Значок появится после следующего входа в систему: GNOME подхватит расширение."
  fi
}

if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  step "Графического сеанса здесь нет. Значок запустится при входе в рабочий стол, а защита работает и без него."
  exit 0
fi

case "${XDG_CURRENT_DESKTOP:-}" in
  *GNOME*)
    if has_host; then
      ok "Значок службы — рядом с часами: есть значок — служба отвечает"
    else
      setup_gnome
    fi
    ;;
  *)
    if has_host; then
      ok "Значок службы — рядом с часами: есть значок — служба отвечает"
    else
      warn "На этом рабочем столе нет области значков: значка не будет, защита работает."
    fi
    ;;
esac

# setsid: значок живёт дальше, когда терминал закроют. Если хост придёт позже, значок
# зарегистрируется сам; уже запущенный экземпляр новый не тронет.
setsid "$VPNLOCK" tray </dev/null >/dev/null 2>&1 &
exit 0
