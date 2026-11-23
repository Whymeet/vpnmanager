#!/bin/bash
# Установка на macOS. Двойной щелчок в Finder или в Терминале: bash install-mac.command
# Только macOS: на другой системе ничего не делает.
cd "$(dirname "$0")" || exit 1
if [ "$(uname -s)" != "Darwin" ]; then
  echo "Это установка для macOS. Для Windows — install-windows.cmd." >&2
  exit 1
fi
exec bash ./setup/macos/install.sh "$@"
