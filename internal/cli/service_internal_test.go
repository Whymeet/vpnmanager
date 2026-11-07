package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPickService(t *testing.T) {
	services := map[string]string{"nginx": "systemd:nginx.service", "nginx.service": "systemd:nginx.service", "ssh": "systemd:ssh.service", "ssh.service": "systemd:ssh.service"}
	env := Env{
		FindService: func(name string) string { return services[name] },
		SameProgram: func(service, command string) bool { return service == "systemd:nginx.service" },
	}
	for _, tt := range []struct {
		name, arg, command, want string
		ok                       bool
	}{
		{"только служба", "nginx", "", "systemd:nginx.service", true},
		{"служба и команда — одна программа: защищается программа", "nginx", "/usr/sbin/nginx", "", true},
		{"разные программы — угадывать нельзя", "ssh", "/usr/bin/ssh", "", false},
		{"суффикс снимает вопрос", "ssh.service", "/usr/bin/ssh", "systemd:ssh.service", true},
		{"только команда", "curl", "/usr/bin/curl", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var errOut bytes.Buffer
			env.Err = &errOut
			got, ok := pickService(env, tt.arg, tt.command)
			if got != tt.want || ok != tt.ok {
				t.Errorf("%q %v", got, ok)
			}
			if !tt.ok && !strings.Contains(errOut.String(), "ssh.service") {
				t.Errorf("нет подсказки: %q", errOut.String())
			}
		})
	}
}

// Вне Linux служб нет, и находить их некому.
func TestPickServiceOffLinux(t *testing.T) {
	if got, ok := pickService(Env{}, "nginx", "/usr/sbin/nginx"); got != "" || !ok {
		t.Errorf("%q %v", got, ok)
	}
}
