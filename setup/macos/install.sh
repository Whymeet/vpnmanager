#!/bin/bash
# Установка appguard на macOS — одной командой из клона, в программе «Терминал»:
#
#   ./setup/macos/install.sh
#
# Идёт по шагам и пишет, что делает: система и права, Go, сборка (это
# подготовка, prepare.sh — от имени человека: сборка под root испортила бы кэш в
# .toolchain), служба, проверка. Пароль администратора спрашивает sudo один раз —
# на шаге «служба». Повторный запуск обновляет установку, настройки сохраняются.
#
# Запущенный по-старому, через sudo, скрипт возвращается к тому, кто вызвал
# sudo, и идёт так же. Claude Code его не запускает (блок правил в
# setup/README.md): скрипт спрашивает пароль и без терминала отказывается.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF="$REPO/setup/macos/install.sh"
BIN="$REPO/bin/appguard"

section() { printf '\n[%d/5] %s\n' "$1" "$2"; }
step() { printf '  · %s\n' "$*"; }
fail() { printf '  ✗ %s\n' "$*" >&2; exit 1; }
indent() { sed -l 's/^/  /'; }

[ "$(uname -s)" = "Darwin" ] || fail "Это не macOS: здесь установка не подходит."
[ -t 0 ] || fail "Установка спрашивает пароль от мака — запусти её в программе «Терминал»: \"$SELF\". В системе ничего не изменено."

if [ "$(id -u)" -eq 0 ]; then
  if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
    fail "Запусти установку от своей учётной записи, без sudo: \"$SELF\". В системе ничего не изменено."
  fi
  exec sudo -H -u "$SUDO_USER" "$SELF" "$@"
fi

printf 'Установка appguard на этот мак. Клон: %s\n' "$REPO"

"$REPO/setup/macos/prepare.sh" --install

section 4 "Ставлю службу — нужен пароль администратора"
step "Терминал спросит пароль от этого мака. Символы при вводе не видны — так и должно быть."
if ! sudo -p '  Пароль от мака: ' "$BIN" install 2>&1 | indent; then
  fail "Служба не поставлена — причина выше. Исправь её и запусти установку ещё раз: \"$SELF\"."
fi

section 5 "Включаю защиту Claude"
"$BIN" status >/dev/null 2>&1 || fail "Служба не отвечает. Причина — в /Library/Logs/appguard/daemon.log."
if ! "$BIN" apply "$REPO/configs/claude-vpn-macos.conf" 2>&1 | indent; then
  fail "Защита Claude не включена — причина выше. Запусти установку ещё раз: \"$SELF\"."
fi
step "Открываю окно «Мои VPN» — добавь свой VPN и нажми «Готово»."
"$BIN" vpn 2>&1 | indent || true

cat <<'EOF'

✓ Готово: защита стоит и включается сама вместе с маком.

  Claude (приложение, Cowork, Claude Code, сайт в браузере) работает только через
  VPN из списка «Мои VPN». Щит в строке меню: с замком — Claude открыт,
  перечёркнутый — закрыт. Изменить список VPN: щит → «Мои VPN…».
EOF
