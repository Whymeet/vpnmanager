package cli

import (
	"encoding/json"
	"fmt"
)

// statusJSON — `appguard status --json`: состояние службы для окна «Мои VPN» и
// других программ, без перевода в слова.
func statusJSON(env Env) int {
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	data, err := json.Marshal(st)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return 1
	}
	fmt.Fprintln(env.Out, string(data))
	return 0
}
