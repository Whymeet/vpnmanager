package dnswatch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// bufLen — буфер BPF: читать из устройства надо ровно его размером.
	bufLen = 1 << 16
	// serversEvery — как часто перечитывать серверы DNS системы.
	serversEvery = 30 * time.Second
)

// System — ответы DNS живой системы: устройство BPF, его открывает только
// root.
type System struct{}

// Listen слушает входящие ответы DNS на интерфейсе iface и отдаёт в got те,
// что пришли от серверов DNS системы, пока не отменён ctx. Ответ со своего
// сервера может получить любая программа — и назвать в нём любое имя.
func (System) Listen(ctx context.Context, iface string, got func(Answer)) error {
	fd, err := openBPF()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	n, err := syscall.SetBpfBuflen(fd, bufLen)
	if err != nil {
		return fmt.Errorf("BPF: размер буфера: %w", err)
	}
	if err := syscall.SetBpfInterface(fd, iface); err != nil {
		return fmt.Errorf("BPF на %s: %w", iface, err)
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		return fmt.Errorf("BPF: %w", err)
	}
	// Только входящие: исходящий «ответ» с порта 53 собрать может любая
	// программа на этом компьютере.
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 0); err != nil {
		return fmt.Errorf("BPF: только входящие: %w", err)
	}
	dlt, err := syscall.BpfDatalink(fd)
	if err != nil {
		return fmt.Errorf("BPF: канальный уровень %s: %w", iface, err)
	}
	prog, err := Filter(dlt)
	if err != nil {
		return fmt.Errorf("BPF на %s: %w", iface, err)
	}
	insns := make([]syscall.BpfInsn, len(prog))
	for i, r := range prog {
		insns[i] = syscall.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := syscall.SetBpf(fd, insns); err != nil {
		return fmt.Errorf("BPF: фильтр: %w", err)
	}
	// Чтение просыпается раз в секунду и без пакетов: так видна отмена ctx.
	if err := syscall.SetBpfTimeout(fd, &syscall.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("BPF: %w", err)
	}
	buf := make([]byte, n)
	var servers []netip.Addr
	var read time.Time
	for ctx.Err() == nil {
		if time.Since(read) > serversEvery {
			servers, read = nameservers(), time.Now()
		}
		m, err := syscall.Read(fd, buf)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("BPF на %s: %w", iface, err)
		}
		for _, pkt := range split(buf[:m]) {
			if a, ok := Parse(dlt, pkt); ok && slices.Contains(servers, a.From) {
				got(a)
			}
		}
	}
	return nil
}

// nameservers — серверы DNS системы сейчас.
func nameservers() []netip.Addr {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	return Nameservers(out)
}

// openBPF открывает свободное устройство /dev/bpfN.
func openBPF() (int, error) {
	for i := 0; i < 256; i++ {
		fd, err := syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, syscall.EBUSY):
			continue
		case errors.Is(err, os.ErrNotExist):
			return -1, errors.New("BPF: все устройства /dev/bpf заняты")
		default:
			return -1, fmt.Errorf("BPF: %w", err)
		}
	}
	return -1, errors.New("BPF: все устройства /dev/bpf заняты")
}
