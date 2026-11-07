//go:build unix

package ipc

import (
	"errors"
	"io/fs"
	"net"
	"os"
)

// Listen открывает канал службы. Подключиться может любой пользователь: статус
// и журнал открыты всем, а кто вправе менять настройки, служба решает сама — по
// учётной записи на другом конце (peerOf).
func Listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func dial(path string) (net.Conn, error) { return net.DialTimeout("unix", path, dialTimeout) }
