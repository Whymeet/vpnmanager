#!/bin/bash
# Настроить vpnlock одной командой: поставить службу, если её нет, и применить
# конфиг. Из клона, в терминале, без sudo (пароль спросит установка, если она
# понадобится):
#
#   ./configs/setup.sh                    # configs/default.conf
#   ./configs/setup.sh configs/work.conf  # другой конфиг
#
# macOS и Linux. Формат конфига описан в configs/default.conf. Запускать можно
# сколько угодно раз: что уже настроено, остаётся как есть. Скрипт только
# добавляет — выход, программу или домен, которых нет в конфиге, он не трогает
# (снять — vpnlock forget, remove, unprotect).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="${1:-$REPO/configs/default.conf}"

step() { printf '  · %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }
indent() { sed 's/^/      /'; }

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) fail "Скрипт — для macOS и Linux. На Windows настрой vpnlock командами из setup/README.md." ;;
esac
[ "$(id -u)" -ne 0 ] || fail "Запусти без sudo, от своей учётной записи: \"$0\". Пароль спросит установка, если она понадобится."
[ -f "$CONF" ] || fail "Нет файла конфига: $CONF"
CONF_DIR="$(cd "$(dirname "$CONF")" && pwd)"

# --- конфиг: сначала проверка целиком, чтобы не применить половину ------------

lines=()
numbers=()
n=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line="${line%$'\r'}"
  line="${line%%#*}"
  read -r -a words <<<"$line"
  [ "${#words[@]}" -gt 0 ] || continue
  key="${words[0]}"
  count=$((${#words[@]} - 1))
  problem=
  case "$key" in
    exit) [ "$count" -ge 2 ] || problem="нужно имя и адрес: exit Германия 203.0.113.5" ;;
    rule) [ "$count" -eq 1 ] && case "${words[1]}" in mine | any) ;; *) false ;; esac || problem="нужно rule mine или rule any" ;;
    app) [ "$count" -ge 1 ] || problem="нужно имя или путь: app claude" ;;
    protect) [ "$count" -ge 1 ] || problem="нужен домен или адрес: protect claude.ai" ;;
    import) [ "$count" -eq 1 ] || problem="нужен один файл: import domains.txt" ;;
    notifications) [ "$count" -eq 1 ] && case "${words[1]}" in on | off) ;; *) false ;; esac || problem="нужно notifications on или off" ;;
    *) problem="нет команды «$key»: есть exit, rule, app, protect, import, notifications" ;;
  esac
  [ -z "$problem" ] || fail "$CONF, строка $n: $problem. Ничего не изменено."
  lines+=("$line")
  numbers+=("$n")
done <"$CONF"
[ "${#lines[@]}" -gt 0 ] || fail "В $CONF нет ни одной команды. Ничего не изменено."

# --- vpnlock: поставить, если его нет или служба не отвечает ------------------

find_vpnlock() {
  if command -v vpnlock >/dev/null 2>&1; then
    command -v vpnlock
  elif [ -x /usr/local/bin/vpnlock ]; then
    echo /usr/local/bin/vpnlock
  fi
}

VL="$(find_vpnlock)"
if [ -z "$VL" ] || ! "$VL" status >/dev/null 2>&1; then
  printf 'vpnlock не установлен или служба не отвечает — ставлю из клона %s\n' "$REPO"
  "$REPO/install.cmd" || fail "Установка не прошла — причина выше. Конфиг не применён."
  VL="$(find_vpnlock)"
  [ -n "$VL" ] && "$VL" status >/dev/null 2>&1 || fail "После установки служба не отвечает. Конфиг не применён."
  printf '\n'
fi

# --- применение ---------------------------------------------------------------

printf 'Применяю конфиг %s\n' "$CONF"
failed=0
skipped=0
domains=0

for i in "${!lines[@]}"; do
  read -r -a words <<<"${lines[$i]}"
  key="${words[0]}"
  args=("${words[@]:1}")
  where="строка ${numbers[$i]}"

  case "$key" in
    app)
      target="${args[*]}"
      case "$target" in "~/"*) target="$HOME/${target#\~/}" ;; esac
      case "$target" in
        /* | ./* | ../*)
          if [ ! -e "$target" ]; then
            warn "$target — нет на этом компьютере, пропускаю"
            skipped=$((skipped + 1))
            continue
          fi
          ;;
      esac
      cmd=(add "$target")
      ;;
    import)
      file="${args[0]}"
      case "$file" in /*) ;; *) file="$CONF_DIR/$file" ;; esac
      cmd=(import "$file")
      domains=1
      ;;
    exit) cmd=(remember "${args[@]}") ;;
    protect)
      cmd=(protect "${args[@]}")
      for a in "${args[@]}"; do
        case "$a" in *:*) ;; *[!0-9.]*) domains=1 ;; esac
      done
      ;;
    *) cmd=("$key" "${args[@]}") ;;
  esac

  step "vpnlock ${cmd[*]}"
  out="$("$VL" "${cmd[@]}" </dev/null 2>&1)"
  code=$?
  if [ "$code" -eq 0 ]; then
    [ -z "$out" ] || printf '%s\n' "$out" | indent
  elif [ "$key" = app ] && grep -q 'уже в списке' <<<"$out"; then
    ok "уже защищено"
  elif [ "$key" = app ] && grep -q '^Приложения «' <<<"$out"; then
    warn "${args[*]} — нет на этом компьютере, пропускаю"
    skipped=$((skipped + 1))
  else
    printf '%s\n' "$out" | indent
    printf '  ✗ не применено (%s)\n' "$where"
    failed=$((failed + 1))
  fi
done

# Домены на Linux перенаправляет systemd-resolved: без него служба их помнит, но
# закрывать начнёт, только когда он появится. Программы и адреса закрыты и так.
if [ "$(uname -s)" = Linux ] && [ "$domains" -eq 1 ] && ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  printf '\n'
  warn "Домены сохранены, но закрываться начнут, когда в системе будет systemd-resolved."
  warn "На Debian: sudo apt install systemd-resolved — служба подхватит его сама."
fi

printf '\n'
"$VL" status | sed 's/^/  /'
printf '\n'
if [ "$failed" -gt 0 ]; then
  fail "Не применено: $failed — причина у каждой строки выше. Исправь и запусти ещё раз: \"$0\"."
fi
if [ "$skipped" -gt 0 ]; then
  printf '✓ Готово. Пропущено программ: %d — когда поставишь их, запусти скрипт ещё раз.\n' "$skipped"
else
  printf '✓ Готово: конфиг применён.\n'
fi
