package netwatch

import "vpnlock/internal/core"

// proxyPoll — опрашивать на Linux нечего: единого системного прокси нет (у GNOME
// свой, у KDE свой, у консольных программ — переменные окружения), поэтому клиент
// VPN в режиме прокси службе не виден. Нужен режим TUN: тогда это обычный туннель.
const proxyPoll = repoll

func proxies(func(port uint16) string) []core.Proxy { return nil }

func listenerOf(uint16) string { return "" }
