package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Канал службы на Windows — два именованных канала: общий (\\.\pipe\appguard) и
// канал администратора (\\.\pipe\appguard-admin). Кто вправе менять настройки,
// решает сама Windows по правам канала: в канал администратора ядро пускает
// только программы, запущенные от имени администратора. У администратора в
// обычном окне PowerShell группа администраторов в маркере доступа только
// запрещающая, и в этот канал его не пустят.
const adminSuffix = "-admin"

// Права на каналы в SDDL. Служба (SY) и администраторы (BA) — полные; все
// вошедшие пользователи (AU) — чтение и запись в общий канал, но без права
// заводить свои экземпляры канала (FILE_CREATE_PIPE_INSTANCE): иначе чужая
// программа отвечала бы клиентам вместо службы.
const (
	publicSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)"
	adminSDDL  = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

// clientAccess — права, с которыми клиент открывает канал: читать и писать
// данные, ничего сверх того, что есть у обычного пользователя.
const clientAccess = windows.GENERIC_READ | windows.FILE_WRITE_DATA

// Listen открывает оба канала службы. Соединение помнит, через какой канал
// пришло (peerOf).
func Listen(path string) (net.Listener, error) {
	pub, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: publicSDDL})
	if err != nil {
		return nil, err
	}
	adm, err := winio.ListenPipe(path+adminSuffix, &winio.PipeConfig{SecurityDescriptor: adminSDDL})
	if err != nil {
		pub.Close()
		return nil, err
	}
	p := &pair{pub: pub, adm: adm, conns: make(chan accepted), done: make(chan struct{})}
	go p.accept(pub, false)
	go p.accept(adm, true)
	return p, nil
}

// dial подключается к каналу администратора, а если Windows туда не пускает, —
// к общему. Клиент не разрешает службе действовать от своего имени
// (SECURITY_ANONYMOUS): программа, занявшая имя канала, не получит прав того,
// кто запустил appguard от имени администратора.
func dial(path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := winio.DialPipeAccessImpLevel(ctx, path+adminSuffix, clientAccess, winio.PipeImpLevelAnonymous)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		conn, err = winio.DialPipeAccessImpLevel(ctx, path, clientAccess, winio.PipeImpLevelAnonymous)
	}
	if err != nil {
		return nil, err
	}
	if err := ownedByService(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// ownedByService — канал завела служба: его владелец — система (SY) или
// администраторы (BA). Обычный пользователь может занять имя канала, пока
// служба не запущена, но владельцем канала будет он сам, и клиент его ответам
// не поверит.
func ownedByService(conn net.Conn) error {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("канал без дескриптора")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("владелец канала: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("владелец канала: %w", err)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("канал открыла не служба appguard, а программа пользователя %s", owner)
}

// peerOf — пришёл ли клиент по каналу администратора, и его процесс.
func peerOf(conn net.Conn) (Peer, error) {
	pc, ok := conn.(*pipeConn)
	if !ok {
		return Peer{}, errors.New("соединение не через канал службы")
	}
	p := Peer{UID: -1, Admin: pc.admin}
	if f, ok := pc.Conn.(interface{ Fd() uintptr }); ok {
		var pid uint32
		if windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid) == nil {
			p.PID = int(pid)
		}
	}
	return p, nil
}

// pipeConn — соединение и канал, через который оно пришло.
type pipeConn struct {
	net.Conn
	admin bool
}

// pair — оба канала службы как один net.Listener.
type pair struct {
	pub, adm net.Listener
	conns    chan accepted
	done     chan struct{}
	once     sync.Once
}

type accepted struct {
	conn net.Conn
	err  error
}

func (p *pair) accept(ln net.Listener, admin bool) {
	for {
		c, err := ln.Accept()
		if err == nil {
			c = &pipeConn{Conn: c, admin: admin}
		}
		select {
		case p.conns <- accepted{c, err}:
		case <-p.done:
			if c != nil {
				c.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (p *pair) Accept() (net.Conn, error) {
	select {
	case a := <-p.conns:
		return a.conn, a.err
	case <-p.done:
		return nil, net.ErrClosed
	}
}

func (p *pair) Close() error {
	p.once.Do(func() { close(p.done) })
	return errors.Join(p.pub.Close(), p.adm.Close())
}

func (p *pair) Addr() net.Addr { return p.pub.Addr() }
