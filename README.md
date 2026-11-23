# vpnmanager — Claude только через VPN (kill switch)

Внутренний проект. Claude Desktop, Cowork, claude.ai/claude.com в браузере и
Claude Code (Windows и WSL) выходят в сеть **только** через VPN на нашем VPS.
Нет VPN или выход не тот — соединения к Anthropic режутся, Claude не грузится.

Основа — форк [appguard](https://github.com/XoDefender/appguard) (коммит
`bdcf89c`). Код лежит здесь целиком, вместе с зависимостями (`vendor/`), и
от репозитория автора не зависит: ничего не скачивает и не обновляет само.

## Что где

| Папка | Что это |
|---|---|
| `cmd/`, `internal/`, `vendor/` | служба `appguard` (Go): Windows, macOS, Linux |
| `configs/claude-vpn.conf`, `configs/claude-vpn-macos.conf` | **наши конфиги** (Windows, macOS): что закрыть (Claude), правило «только мои VPN» |
| `internal/exitsui/` | **окно «Мои VPN» для Windows** (PowerShell + WinForms) |
| `internal/cli/vpn_dialog.go`, `vpn_darwin.go` | **окно «Мои VPN» для macOS** (системные диалоги osascript) |
| `wsl/` | **наш kill switch для WSL** (bash + nftables): Claude Code в WSL |
| `setup/` | установка appguard; `setup/README.md` — подробная инструкция |
| `catalog/` | каталог приложений (домены, адреса) |

Почему два слоя: трафик WSL2 идёт через NAT Windows, а фильтры appguard
привязаны к процессам Windows — процессы внутри WSL под них не попадают.

## Установка

У каждой системы свой файл запуска: **`install-windows.cmd`** — Windows,
**`install-mac.command`** — macOS. Каждый запускает только установку своей
системы со своим конфигом (это проверяет тест `TestInstallersAreSplit`).
Старый общий `install.cmd` оставлен для совместимости.

VPN — в режиме полного туннеля (в v2rayN — режим TUN).

### Windows — Claude Desktop, Cowork, браузеры: одна команда

Двойной щелчок по **`install-windows.cmd`** в папке проекта на диске C: (или в
PowerShell: `C:\vpnmanager\install-windows.cmd`). Windows один раз спросит разрешение — «Да». Дальше
само:

1. сборка и служба (стартует вместе с Windows, после перезагрузки тоже);
2. защита Claude из `configs/claude-vpn.conf`: приложение и сайты Claude — только
   через VPN из списка, правило «только мои VPN»;
3. окно **«Мои VPN»**: «Добавить этот VPN» (текущий проверенный выход) или
   название + IP выхода вручную; список и «Удалить». Пока список пуст — Claude
   закрыт.

Потом список меняется через щит у часов → **«Мои VPN…»** (Windows спросит
разрешение: список выходов меняет только администратор) или `appguard vpn`.
Повторный `install-windows.cmd` обновляет программу, список VPN сохраняется.

Папку проекта после установки не переносить: из неё идёт обновление.

### macOS — Claude Desktop, Cowork, Claude Code, браузеры: одна команда

Двойной щелчок по **`install-mac.command`** в Finder или в программе «Терминал»,
из папки проекта, без sudo:

```bash
bash install-mac.command
```

Терминал один раз спросит пароль от мака. Дальше само: сборка, служба
(стартует вместе с маком), защита Claude из `configs/claude-vpn-macos.conf`
(приложение Claude, команда `claude` — Claude Code, сайты Claude во всех
браузерах) и окно **«Мои VPN»**: «Добавить текущий VPN», «Добавить VPN по
адресу…», «Удалить VPN…». Потом — щит в строке меню → **«Мои VPN…»** или
`appguard vpn`. Менять список может пользователь из группы администраторов.

### WSL — Claude Code

```bash
cd ~/project/vpnmanager/wsl
sudo ./install.sh <IP-выхода-VPN>
claude-guard --status     # Claude: open / closed
```

- Раз в 5 с проверяется выход (Cloudflare и ipify, отдельно IPv4 и IPv6). Совпал
  с VPS — сети Anthropic открыты; нет — закрыты в nftables (таблица
  `inet claude_ks`), запущенный Claude Code завершается.
- Неясность, старт WSL, остановка или падение службы — закрыто.
- Команда `claude` идёт через `claude-guard`: без VPN не запускается.
- Настройки — `/etc/claude-killswitch.conf`, журнал — `journalctl -u claude-killswitch -f`,
  удаление — `sudo ./uninstall.sh`.

## Разработка

```bash
./setup/linux/prepare.sh          # Go в .toolchain/ и сборка bin/appguard
tools/go test ./...
GOOS=windows GOARCH=amd64 tools/go build ./... && GOOS=windows tools/go vet ./...
```

Правки автора appguard — только вручную, после просмотра:
`git fetch upstream && git log main..upstream/main && git merge upstream/main`.

## Ограничения

- Защита от случайностей (VPN отвалился, забыли включить), а не от
  администратора компьютера: с правами admin/sudo всё выключается.
- На Windows appguard режет сеть, а не запуск: окно Claude откроется, но
  ничего не загрузит. В WSL блокируется и запуск `claude`.
- Split tunneling в VPN-клиенте ломает гарантию — только полный туннель.
- У исходного appguard нет лицензии: формально его код нельзя
  распространять без разрешения автора. Для внутреннего использования
  желательно получить его согласие.
