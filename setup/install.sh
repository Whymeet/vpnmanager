#!/bin/sh
# Куда уходит sh из первой строки install.cmd: установка своей системы. Выбор
# здесь, а не в самом install.cmd: первую строку читает и cmd.exe, и лишние знаки
# в ней ему ни к чему.
case "$(uname -s)" in
  Linux) system=linux ;;
  *) system=macos ;;
esac
exec bash "$(dirname "$0")/$system/install.sh" "$@"
