#!/bin/bash
# Подготовка к установке vpnlock на Linux. Запускается БЕЗ sudo — от имени
# человека: её выполняет установка (./install.cmd) первыми тремя шагами, а Claude
# Code может запустить её сам, без пароля:
#
#   ./setup/linux/prepare.sh
#
# 1. Проверяет, что это Linux с systemd и новым ядром и что у пользователя есть
#    права администратора. Права проверяются первыми: без них установка невозможна,
#    и скрипт останавливается, ничего не скачав и не собрав.
# 2. Находит Go не старше версии из go.mod. Если его нет — ставит Go в .toolchain/
#    клона: без пароля и без изменений в системе, удаляется вместе с клоном.
# 3. Собирает инструмент в bin/vpnlock.
#
# С --install её запускает установка: шаги нумеруются из шести, дальше служба.
# С --update — «sudo vpnlock update», уже от имени человека; новую версию ставит
# сама команда.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  "" | --update) TOTAL=3 ;;
  --install) TOTAL=6 ;;
  *) printf '✗ Подготовка принимает только --install или --update, а получено «%s».\n' "$MODE" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN="$REPO/.toolchain"

# Go, который ставится, если подходящего нет. Суммы — со страницы go.dev/dl.
GO_VERSION="1.27.3"
GO_SHA256_arm64="a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49"
GO_SHA256_amd64="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"

n=0
section() { n=$((n + 1)); printf '\n[%d/%d] %s\n' "$n" "$TOTAL" "$*"; }
step() { printf '  · %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
fail() { printf '  ✗ %s\n' "$*" >&2; exit 1; }

# version_ge A B — A не меньше B (версии вида 1.27.2 или 1.25).
version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

# --- система и права ---------------------------------------------------------

section "Проверяю систему и права"
[ "$(uname -s)" = "Linux" ] || fail "Это не Linux: здесь подготовка не подходит."
[ "$(id -u)" -ne 0 ] || fail "Подготовку запускают без sudo — от своего пользователя."

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "Архитектура $(uname -m) не поддерживается: нужна x86_64 или aarch64." ;;
esac

[ -d /run/systemd/system ] || fail "Нет systemd: vpnlock работает службой systemd, а эта система (или контейнер) запущена без него."

kernel="$(uname -r)"
kernel="${kernel%%-*}"
version_ge "$kernel" "5.15" || fail "Нужно ядро Linux 5.15 или новее, а здесь $kernel."

user="$(id -un)"
is_admin=
# По имени, а не по текущему процессу: «sudo vpnlock update» запускает подготовку
# без дополнительных групп, а права у человека от этого не исчезают.
for group in $(id -nG "$user"); do
  case "$group" in sudo | wheel | admin) is_admin=1 ;; esac
done
[ -n "$is_admin" ] || fail "У пользователя $user нет прав администратора (группы sudo, wheel или admin), поэтому установить vpnlock нельзя. В системе ничего не изменено."

ok "Linux $kernel, $arch, пользователь $user — администратор"

# --- Go ----------------------------------------------------------------------

section "Ищу Go для сборки"
need="$(awk '$1 == "go" { print $2; exit }' "$REPO/go.mod")"

# find_go печатает путь к Go не старше $need. GOTOOLCHAIN=local и запуск из /
# не дают go.mod клона скачать другой тулчейн во время проверки.
find_go() {
  local g v
  for g in "$TOOLCHAIN/go/bin/go" "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go; do
    [ -n "$g" ] && [ -x "$g" ] || continue
    v="$(cd / && GOTOOLCHAIN=local "$g" env GOVERSION 2>/dev/null)" || continue
    v="${v#go}"; v="${v%%[!0-9.]*}"
    if version_ge "$v" "$need"; then echo "$g"; return 0; fi
  done
  return 1
}

GO_TMP=""
trap 'rm -rf "$GO_TMP"' EXIT

install_go() {
  local sum_var="GO_SHA256_$arch"
  command -v curl >/dev/null 2>&1 || fail "Нет программы curl: поставь её (sudo apt install curl) и запусти ещё раз."
  GO_TMP="$(mktemp -d)"
  step "Go $need+ не найден — скачиваю Go $GO_VERSION (около 70 МБ) в $TOOLCHAIN: он нужен только для сборки, пароль не нужен"
  curl -fL --retry 3 --progress-bar -o "$GO_TMP/go.tgz" "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
    || fail "Не удалось скачать Go с go.dev. Проверь интернет (можно включить VPN) и запусти ещё раз."
  echo "${!sum_var}  $GO_TMP/go.tgz" | sha256sum -c - >/dev/null \
    || fail "Контрольная сумма Go не сошлась: файл повреждён или подменён. Ничего не установлено."
  step "Контрольная сумма сошлась, распаковываю"
  tar -xzf "$GO_TMP/go.tgz" -C "$GO_TMP"
  mkdir -p "$TOOLCHAIN"
  rm -rf "$TOOLCHAIN/go"
  mv "$GO_TMP/go" "$TOOLCHAIN/go"
}

if ! GO="$(find_go)"; then
  install_go
  GO="$(find_go)" || fail "Go поставлен, но не запускается: $TOOLCHAIN/go/bin/go."
fi
ok "$(cd / && GOTOOLCHAIN=local "$GO" env GOVERSION): $GO"

# --- сборка ------------------------------------------------------------------

# Всё нужное для сборки лежит в клоне (vendor/), так что сеть не нужна.
# GOENV=off — чужие настройки Go пользователя не влияют на сборку; CGO_ENABLED=0 —
# не нужен компилятор C. -trimpath — в файл не попадают пути клона.
section "Собираю vpnlock"
[ -d "$TOOLCHAIN/cache" ] || step "Первая сборка занимает пару минут, следующие — секунды"
mkdir -p "$REPO/bin"
(
  cd "$REPO"
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    GOPATH="$TOOLCHAIN/gopath" GOCACHE="$TOOLCHAIN/cache" \
    "$GO" build -trimpath -ldflags="-s -w" -o "$REPO/bin/vpnlock" ./cmd/vpnlock
) || fail "Сборка не прошла — вывод выше. В системе ничего не изменено."
built="$("$REPO/bin/vpnlock" version)" || fail "Собранный bin/vpnlock не запускается."
ok "vpnlock $built — $REPO/bin/vpnlock"

[ -z "$MODE" ] || exit 0

printf '\nВ системе пока ничего не изменено. Установка — в терминале:\n\n'
printf '  "%s/install.cmd"\n\n' "$REPO"
printf 'Она повторит эти шаги за секунды, поставит службу и один раз спросит пароль.\n'
