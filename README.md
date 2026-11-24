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

Что нужно везде:

- **VPN в режиме полного туннеля** — через него идёт весь трафик компьютера (в
  v2rayN — режим **TUN**; режим «системный прокси» не подходит). Включи его до
  установки: без VPN Claude после установки сразу закроется.
- **Права администратора** на компьютере.
- **Интернет** на первый запуск: установка один раз скачает Go (~70 МБ) и
  соберёт программу; дальше сеть для этого не нужна.
- **IP выхода своего VPN** — адрес, который видят сайты (не всегда совпадает с
  адресом сервера). Узнать: включи VPN и открой
  <https://1.1.1.1/cdn-cgi/trace> — строка `ip=`.

У каждой системы свой файл запуска, они не пересекаются:

| Система | Что защищает | Файл запуска |
|---|---|---|
| Windows 10/11 | Claude Desktop, Cowork, Claude Code для Windows, сайты Claude во всех браузерах | `install-windows.cmd` |
| macOS 12+ | Claude Desktop, Cowork, Claude Code (`claude`), сайты Claude во всех браузерах | `install-mac.command` |
| WSL (Ubuntu в Windows) | Claude Code внутри WSL | `wsl/install.sh` |

На Windows с WSL ставятся обе части: Windows-защита не видит программ внутри WSL.

---

### Windows

**1. Скачать проект на диск C:**

С Git (если нет — `winget install --id Git.Git`, затем новое окно PowerShell):

```powershell
git clone https://github.com/Whymeet/vpnmanager.git C:\vpnmanager
```

Без Git: на странице репозитория **Code → Download ZIP**, распаковать на диск
`C:\` и переименовать получившуюся папку `vpnmanager-main` в `vpnmanager` —
чтобы `install-windows.cmd` лежал прямо в `C:\vpnmanager` (а не в
`C:\vpnmanager\vpnmanager-main`). Обновления из ZIP-копии не приходят: для них
нужен `git clone`.

> Папка должна лежать на обычном диске (`C:\…`), не на `\\wsl$\…`. После
> установки её не переносить и не удалять: из неё идут обновления.

**2. Запустить установку** — двойной щелчок по `C:\vpnmanager\install-windows.cmd`
(или в PowerShell: `C:\vpnmanager\install-windows.cmd`).

- Окно покажет шаги `[1/5] … [5/5]`; первый раз — несколько минут (сборка).
- Windows спросит «Разрешить этому приложению вносить изменения?» — **«Да»**
  (один раз).
- Откроется окно **«Мои VPN»**.

**3. Добавить свой VPN** в окне «Мои VPN»:

- VPN включён → **«Добавить этот VPN»**;
- или впиши название и IP выхода → **«Добавить»** (можно несколько VPN);
- **«Готово»**.

**4. Проверить:**

- у часов появился щит: с замком — Claude открыт, перечёркнутый — закрыт;
- выключи VPN → через ~10 с щит перечёркнут, Claude Desktop и claude.ai не грузятся;
- включи VPN → через ~10 с всё работает.

Подробная проверка — в PowerShell **от имени администратора**: `appguard status`,
`appguard check`.

**Потом:**

| Что | Как |
|---|---|
| изменить список VPN | щит у часов → **«Мои VPN…»** (Windows спросит разрешение) |
| обновить | `cd C:\vpnmanager; git pull`, затем снова `install-windows.cmd` — список VPN сохранится |
| удалить | PowerShell от имени администратора: `appguard uninstall` |

---

### macOS

**1. Скачать проект** — в программе «Терминал»:

```bash
git clone https://github.com/Whymeet/vpnmanager.git ~/vpnmanager
cd ~/vpnmanager
```

Если мак предложит поставить «инструменты разработчика» для `git` —
согласиться и повторить команду. Скачивать ZIP через браузер не советуем:
macOS помечает такие файлы и не даёт их запустить двойным щелчком.

**2. Запустить установку** — в том же Терминале, **без sudo**:

```bash
bash install-mac.command
```

- Шаги `[1/5] … [5/5]`; первый раз — несколько минут (сборка).
- Терминал спросит **пароль от мака** (символы при вводе не видны — так и
  должно быть).
- Откроется окно **«Мои VPN»**.

**3. Добавить свой VPN** в окне «Мои VPN»:

- VPN включён → **«Добавить текущий VPN (…)»** → название → OK;
- или **«Добавить VPN по адресу…»** → IP выхода → название;
- **«Готово»**.

**4. Проверить:**

- в строке меню у часов щит: с замком — Claude открыт, перечёркнутый — закрыт;
- выключи VPN → через ~10 с Claude, `claude` в Терминале и claude.ai в браузере
  не работают;
- включи VPN → всё работает.

Подробно: `appguard status`, `appguard check`.

**Потом:**

| Что | Как |
|---|---|
| изменить список VPN | щит в строке меню → **«Мои VPN…»** или `appguard vpn` |
| обновить | `cd ~/vpnmanager && git pull && bash install-mac.command` — список VPN сохранится |
| удалить | `sudo appguard uninstall` |

---

### WSL (Claude Code в Ubuntu на Windows)

Нужен WSL2 с включённым systemd (в Ubuntu 24.04 включён по умолчанию; если нет —
в `/etc/wsl.conf` добавить `[boot]` / `systemd=true` и в PowerShell выполнить
`wsl --shutdown`).

**1. Скачать проект** — в терминале WSL:

```bash
git clone https://github.com/Whymeet/vpnmanager.git ~/vpnmanager
cd ~/vpnmanager/wsl
```

**2. Установить**, указав IP выхода своего VPN (несколько — через пробел):

```bash
sudo ./install.sh 203.0.113.10
```

- Спросит пароль от Ubuntu.
- Поставит `nftables`; если сервер пакетов Ubuntu через VPN не отвечает, сам
  возьмёт зеркало.
- В конце покажет `Claude: open` (VPN включён и IP совпал).

**3. Открыть новый терминал WSL** — в старом команда `claude` ещё без проверки.

**4. Проверить:**

```bash
claude-guard --status     # Claude: open / closed
```

- выключи VPN → через ~10 с `claude` пишет «нет проверенного VPN», запущенный
  Claude Code закрывается;
- включи VPN → `claude` запускается.

Как это устроено: раз в 5 с выход проверяется по двум источникам (Cloudflare и
ipify), отдельно IPv4 и IPv6. Совпал со списком — сети Anthropic открыты; нет —
закрыты в nftables (таблица `inet claude_ks`). При старте WSL, сбое проверки
или падении службы — закрыто.

**Потом:**

| Что | Как |
|---|---|
| изменить список VPN | `sudo ./install.sh <IP> [IP…]` ещё раз или правка `ALLOWED_EXITS` в `/etc/claude-killswitch.conf`, затем `sudo systemctl restart claude-killswitch` |
| журнал | `journalctl -u claude-killswitch -f` |
| обновить | `cd ~/vpnmanager && git pull && cd wsl && sudo ./install.sh` (без IP — список не меняется) |
| удалить | `cd ~/vpnmanager/wsl && sudo ./uninstall.sh` |

---

### Если что-то не так

| Что видно | Что делать |
|---|---|
| Claude закрыт, хотя VPN включён | в «Мои VPN» нет этого VPN или IP выхода другой — сверь с <https://1.1.1.1/cdn-cgi/trace>; в v2rayN должен быть режим TUN |
| Windows: `appguard` не найден | открой **новое** окно PowerShell — старое не знает о новой программе |
| Windows: щита нет у часов | он может быть спрятан за стрелкой `^` у часов; служба не отвечает — `appguard status` |
| WSL: установка долго стоит на «ставлю nftables» | Ctrl+C, `sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a`, запустить установку снова |
| WSL: `claude` запускается без проверки | открой новый терминал; `type claude` должно показать функцию |

Подробнее про устройство службы — `setup/README.md`.

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
