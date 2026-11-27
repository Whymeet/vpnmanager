package service

import (
	"cmp"
	"context"
	"time"

	"appguard/internal/core"
)

// Как часто служба спрашивает свой резолвер по петле (если Deps не задаёт
// иначе), сколько ждёт ответа и после скольких промахов подряд снимает
// направление доменов на него.
const (
	resolverEvery  = 3 * time.Second
	resolverWait   = time.Second
	resolverMisses = 2
)

// resolverLoop следит, доходят ли до резолвера службы запросы по петле.
//
// Клиенты VPN на sing-box (v2RayTun, Hiddify, NekoBox) в режиме туннеля
// запрещают всем соединения на порт 53 мимо своего туннеля — петлю тоже. На
// Windows их запрет окончательный, если их подуровень WFP оказался раньше
// подуровня appguard, и тогда имена защищённых доменов не разрешаются вовсе:
// сервисы не открываются даже через проверенный VPN. Пока так, домены на
// службу не направляются — их разрешает DNS системы (у такого клиента — через
// его туннель). Адреса, уже лежащие в таблицах, закрыты мимо проверенного VPN
// как и были; новые адреса домена в таблицы до возврата не попадают. Резолвер
// снова отвечает — домены возвращаются на службу.
func (e *engine) resolverLoop(ctx context.Context) {
	up := e.d.ResolverUp
	if up == nil {
		if !e.dnsAddr.IsValid() {
			return
		}
		up = func(ctx context.Context) bool { return e.resolverAnswers(ctx, resolverWait) }
	}
	every := cmp.Or(e.d.ResolverEvery, resolverEvery)
	tick := time.NewTicker(every)
	defer tick.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if up(ctx) {
			misses = 0
			e.setBypass(false)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if misses++; misses >= resolverMisses {
			e.setBypass(true)
		}
	}
}

// setBypass включает и выключает обход резолвера службы.
func (e *engine) setBypass(on bool) {
	e.mu.Lock()
	changed := e.dnsBypass != on
	e.dnsBypass = on
	e.mu.Unlock()
	if !changed {
		return
	}
	text := "резолвер службы снова отвечает — защищённые домены снова разрешает служба"
	if on {
		text = "резолвер службы не отвечает: запросы на порт 53 режет файрвол (клиент VPN с защитой от утечек DNS) — защищённые домены пока разрешает DNS системы"
	}
	kind := core.KindGuard
	if on {
		kind = core.KindError
	}
	e.d.Logf("%s", text)
	e.record([]core.Event{{Time: e.d.Now(), Kind: kind, Text: text}})
	e.syncDNS()
}
