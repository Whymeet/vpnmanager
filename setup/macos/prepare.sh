#!/bin/bash
# Подготовка к установке vpnlock на macOS. Запускается БЕЗ sudo — от имени
# человека: её выполняет установка (./setup/macos/install.sh) первыми тремя
# шагами, а Claude Code может запустить её сам, без пароля:
#
#   ./setup/macos/prepare.sh
#
# 1. Проверяет, что это macOS 12+ и что у пользователя есть права администратора.
#    Права проверяются первыми: без них установка невозможна, и скрипт
#    останавливается, ничего не скачав и не собрав.
# 2. Находит Go не старше версии из go.mod. Если его нет — ставит Go в .toolchain/
#    клона: без пароля и без изменений в системе, удаляется вместе с клоном.
# 3. Собирает инструмент в bin/vpnlock.
#
# С --install её запускает установка: шаги нумеруются из пяти, дальше служба.
# С --update — «sudo vpnlock update», уже от имени человека; новую версию ставит
# сама команда.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  "" | --update) TOTAL=3 ;;
  --install) TOTAL=5 ;;
  *) printf '✗ Подготовка принимает только --install или --update, а получено «%s».\n' "$MODE" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN="$REPO/.toolchain"

# Go, который ставится, если подходящего нет. Суммы — со страницы go.dev/dl.
GO_VERSION="1.27.2"
GO_SHA256_arm64="76812b213b1b2302c978d28fa52fa92d541704b9e7d9d5db8002c50e4018c4c5"
GO_SHA256_amd64="587b59182488b23aa6e5fc25110405a3e0e5b38ed2f5b2f46ed13c32aee356fe"

n=0
section() { n=$((n + 1)); printf '\n[%d/%d] %s\n' "$n" "$TOTAL" "$*"; }
step() { printf '  · %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
fail() { printf '  ✗ %s\n' "$*" >&2; exit 1; }

# --- система и права ---------------------------------------------------------

section "Проверяю систему и права"
[ "$(uname -s)" = "Darwin" ] || fail "Это не macOS: здесь подготовка не подходит."
macos="$(sw_vers -productVersion)"
[ "${macos%%.*}" -ge 12 ] || fail "Нужна macOS 12 или новее, а здесь $macos."
[ "$(id -u)" -ne 0 ] || fail "Подготовку запускают без sudo — от своего пользователя."

user="$(id -un)"
if ! dsmemberutil checkmembership -U "$user" -G admin 2>/dev/null | grep -qx "user is a member of the group"; then
  fail "У пользователя $user нет прав администратора, поэтому установить vpnlock нельзя. В системе ничего не изменено. Нужна учётная запись администратора: Системные настройки → Пользователи и группы."
fi

# Сборка под родную архитектуру, даже если терминал запущен через Rosetta.
if [ "$(sysctl -in hw.optional.arm64)" = "1" ]; then arch=arm64; else arch=amd64; fi
ok "macOS $macos, $arch, пользователь $user — администратор"

# --- Go ----------------------------------------------------------------------

section "Ищу Go для сборки"
need="$(awk '$1 == "go" { print $2; exit }' "$REPO/go.mod")"

# version_ge A B — A не меньше B (версии вида 1.27.2 или 1.25).
version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

# find_go печатает путь к Go не старше $need. GOTOOLCHAIN=local и запуск из /
# не дают go.mod клона скачать другой тулчейн во время проверки.
find_go() {
  local g v
  for g in "$TOOLCHAIN/go/bin/go" "$(command -v go 2>/dev/null || true)" /opt/homebrew/bin/go /usr/local/go/bin/go; do
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
  GO_TMP="$(mktemp -d)"
  step "Go $need+ не найден — скачиваю Go $GO_VERSION (около 70 МБ) в $TOOLCHAIN: он нужен только для сборки, пароль не нужен"
  curl -fL --retry 3 --progress-bar -o "$GO_TMP/go.tgz" "https://go.dev/dl/go${GO_VERSION}.darwin-${arch}.tar.gz" \
    || fail "Не удалось скачать Go с go.dev. Проверь интернет (можно включить VPN) и запусти ещё раз."
  echo "${!sum_var}  $GO_TMP/go.tgz" | shasum -a 256 -c - >/dev/null \
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
# не нужен компилятор C (Xcode). -trimpath — в файл не попадают пути клона.
section "Собираю vpnlock"
[ -d "$TOOLCHAIN/cache" ] || step "Первая сборка занимает пару минут, следующие — секунды"
mkdir -p "$REPO/bin"
(
  cd "$REPO"
  GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" \
    GOPATH="$TOOLCHAIN/gopath" GOCACHE="$TOOLCHAIN/cache" \
    "$GO" build -trimpath -ldflags="-s -w" -o "$REPO/bin/vpnlock" ./cmd/vpnlock
) || fail "Сборка не прошла — вывод выше. В системе ничего не изменено."
# Подпись без сертификата, но с именем службы: иначе macOS называет файл «a.out»,
# и в списке фоновых объектов его легко принять за чужой и выключить.
codesign --force --sign - --identifier com.vpnlock.daemon "$REPO/bin/vpnlock" 2>/dev/null \
  || fail "Не удалось подписать bin/vpnlock (codesign)."
built="$("$REPO/bin/vpnlock" version)" || fail "Собранный bin/vpnlock не запускается."
ok "vpnlock $built — $REPO/bin/vpnlock"

[ -z "$MODE" ] || exit 0

printf '\nВ системе пока ничего не изменено. Установка — в программе «Терминал»:\n\n'
printf '  "%s/setup/macos/install.sh"\n\n' "$REPO"
printf 'Она повторит эти шаги за секунды, поставит службу и один раз спросит пароль от этого мака.\n'
