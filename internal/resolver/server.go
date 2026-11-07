package resolver

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// queryTimeout — сколько резолвер тратит на один запрос программы.
const queryTimeout = 4 * time.Second

// Server — DNS-сервер службы на локальном адресе.
type Server struct {
	Resolver *Resolver
	// Match — защищённый домен, к которому относится имя. Система шлёт сюда
	// только защищённые домены; имя вне них приходит, лишь пока она не
	// перечитала /etc/resolver после снятия защиты.
	Match func(name string) (domain string, ok bool)
	// Learn кладёт адреса в таблицы файрвола. Ответ программе уходит только
	// после него; ошибка — программа получает SERVFAIL, а не адрес мимо таблиц.
	Learn func(ctx context.Context, domain string, addrs []netip.Addr) error
	Logf  func(format string, args ...any)

	udp, tcp *dns.Server
	addr     netip.AddrPort
}

// Start слушает addr по UDP и TCP («127.0.0.1:0» — любой свободный порт).
func (s *Server) Start(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	ln, err := net.Listen("tcp", ap.String())
	if err != nil {
		pc.Close()
		return err
	}
	s.addr = ap
	s.udp = &dns.Server{PacketConn: pc, Handler: s}
	s.tcp = &dns.Server{Listener: ln, Handler: s}
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	return nil
}

// Addr — где слушает сервер.
func (s *Server) Addr() netip.AddrPort { return s.addr }

// Stop закрывает сервер.
func (s *Server) Stop() {
	if s.udp != nil {
		s.udp.Shutdown()
	}
	if s.tcp != nil {
		s.tcp.Shutdown()
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		s.reply(w, req, dns.RcodeFormatError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	domain, ok := s.Match(Normalize(req.Question[0].Name))
	if !ok {
		// Защиту сняли, а система ещё шлёт имя сюда: отвечаем как обычный DNS,
		// ничего не кладя в таблицы. Отказ оставил бы имя на эти секунды совсем
		// без адреса.
		ans, err := first(ctx, s.Resolver.Up.Primary, req)
		if err != nil {
			s.reply(w, req, dns.RcodeServerFailure)
			return
		}
		s.write(w, req, ans)
		return
	}
	ans, addrs, err := s.Resolver.Resolve(ctx, req)
	if err != nil {
		s.Logf("резолвер: %s: %v", req.Question[0].Name, err)
		s.reply(w, req, dns.RcodeServerFailure)
		return
	}
	if len(addrs) > 0 {
		if err := s.Learn(ctx, domain, addrs); err != nil {
			s.Logf("резолвер: адреса %s не попали в таблицы: %v", req.Question[0].Name, err)
			s.reply(w, req, dns.RcodeServerFailure)
			return
		}
	}
	s.write(w, req, ans)
}

// write отправляет ответ под номером запроса; по UDP — не больше, чем принимает
// спросивший (остальное — с флагом TC, он переспросит по TCP).
func (s *Server) write(w dns.ResponseWriter, req, ans *dns.Msg) {
	ans.Id = req.Id
	if _, udp := w.LocalAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		ans.Truncate(size)
	}
	w.WriteMsg(ans)
}

func (s *Server) reply(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	w.WriteMsg(m)
}
