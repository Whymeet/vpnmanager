#!/bin/bash
# Установка appguard на Linux — одной командой из клона, в терминале:
#
#   ./install.cmd
#
# Идёт по шагам и пишет, что делает: система и права, Go, сборка (это подготовка,
# prepare.sh — от имени человека: сборка под root испортила бы кэш в .toolchain),
# служба, значок, проверка. Пароль спрашивает sudo один раз — на шаге «служба».
# Повторный запуск обновляет установку, настройки сохраняются.
#
# Запущенный через sudo, скрипт возвращается к тому, кто вызвал sudo, и идёт так
# же. Claude Code его не запускает (блок правил в setup/README.md): скрипт
# спрашивает пароль и без терминала отказывается.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF="$REPO/install.cmd"
BIN="$REPO/bin/appguard"

section() { printf '\n[%d/6] %s\n' "$1" "$2"; }
step() { printf '  · %s\n' "$*"; }
fail() { printf '  ✗ %s\n' "$*" >&2; exit 1; }
indent() { sed -u 's/^/  /'; }

[ "$(uname -s)" = "Linux" ] || fail "Это не Linux: здесь установка не подходит."
[ -t 0 ] || fail "Установка спрашивает пароль — запусти её в терминале: \"$SELF\". В системе ничего не изменено."

if [ "$(id -u)" -eq 0 ]; then
  if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
    fail "Запусти установку от своей учётной записи, без sudo: \"$SELF\". В системе ничего не изменено."
  fi
  exec sudo -H -u "$SUDO_USER" "$SELF" "$@"
fi

printf 'Установка appguard на этот компьютер. Клон: %s\n' "$REPO"

"$REPO/setup/linux/prepare.sh" --install

has_nft() { [ -x /usr/sbin/nft ] || [ -x /sbin/nft ] || command -v nft >/dev/null 2>&1; }

# Пакет nftables есть в любом дистрибутиве, но поставлен не везде.
install_nft() {
  step "Нет программы nft — ставлю пакет nftables"
  if command -v apt-get >/dev/null 2>&1; then
    sudo -p '  Пароль: ' apt-get install -y nftables
  elif command -v dnf >/dev/null 2>&1; then
    sudo -p '  Пароль: ' dnf install -y nftables
  elif command -v pacman >/dev/null 2>&1; then
    sudo -p '  Пароль: ' pacman -S --noconfirm nftables
  elif command -v zypper >/dev/null 2>&1; then
    sudo -p '  Пароль: ' zypper --non-interactive install nftables
  else
    return 1
  fi
}

section 4 "Ставлю службу — нужен пароль администратора"
step "Терминал спросит пароль. Символы при вводе не видны — так и должно быть."
if ! has_nft; then
  install_nft 2>&1 | indent || true
  has_nft || fail "Не удалось поставить пакет nftables — поставь его сам и запусти установку ещё раз: \"$SELF\"."
fi
if ! sudo -p '  Пароль: ' "$BIN" install 2>&1 | indent; then
  fail "Служба не поставлена — причина выше. Исправь её и запусти установку ещё раз: \"$SELF\"."
fi

# Значок не защищает, поэтому шаг не может прервать установку: не вышло — он скажет
# почему, и установка идёт дальше.
section 5 "Ставлю значок рядом с часами"
bash "$REPO/setup/linux/tray.sh" /opt/appguard/bin/appguard 2>&1 | indent || true

section 6 "Проверяю службу"
"$BIN" status 2>&1 | indent || fail "Служба не отвечает. Причина — в /var/log/appguard/daemon.log."

cat <<'DONE'

✓ Готово: appguard установлен и стартует вместе с системой.

Дальше — три шага, без sudo:
  appguard apply            программы и сервисы из готового конфига (configs/linux.conf)
  appguard remember <имя>   свой выход VPN: подключи VPN и запомни; повтори для каждого
  appguard rule mine        сервисы открыты только через твои выходы

Защитить что-то своё — одна команда, сразу и без обучения:
  appguard add firefox        программа или служба по имени
  appguard add /opt/app/run   или по пути

  appguard status   что защищено и какой выход сейчас
  appguard help     все команды
DONE
