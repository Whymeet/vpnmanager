package apps

import "testing"

func TestCommandTarget(t *testing.T) {
	for real, want := range map[string]struct {
		target string
		dir    bool
	}{
		// Claude Code: файл назван версией, новые версии — рядом.
		"/Users/me/.local/share/claude/versions/2.1.301": {"/Users/me/.local/share/claude/versions", true},
		// Homebrew: папка версии не защищается, иначе обновление сняло бы защиту.
		"/opt/homebrew/Cellar/gh/2.60.0/bin/gh":    {"/opt/homebrew/Cellar/gh", true},
		"/usr/local/Cellar/gh/2.60.0_1/bin/gh":     {"/usr/local/Cellar/gh", true},
		"/opt/homebrew/Cellar/foo/1.2/libexec/foo": {"/opt/homebrew/Cellar/foo", true},
		// Пакеты node — папка пакета, с областью и без.
		"/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js":                              {"/opt/homebrew/lib/node_modules/@openai/codex", true},
		"/Users/me/.nvm/versions/node/v20.1.0/lib/node_modules/@google/gemini-cli/dist/index.js": {"/Users/me/.nvm/versions/node/v20.1.0/lib/node_modules/@google/gemini-cli", true},
		"/usr/local/lib/node_modules/tool/cli.js":                                                {"/usr/local/lib/node_modules/tool", true},
		// Своя папка программы.
		"/Users/me/tools/agent/agent": {"/Users/me/tools/agent", true},
		"/opt/vendor/app/run":         {"/opt/vendor/app", true},
		// Общие папки — только сам файл.
		"/usr/local/bin/foo":                      {"/usr/local/bin/foo", false},
		"/opt/homebrew/bin/foo":                   {"/opt/homebrew/bin/foo", false},
		"/usr/bin/curl":                           {"/usr/bin/curl", false},
		"/usr/libexec/tool/x":                     {"/usr/libexec/tool/x", false},
		"/System/Library/x/y":                     {"/System/Library/x/y", false},
		"/Users/me/foo":                           {"/Users/me/foo", false},
		"/Users/me/go/bin/foo":                    {"/Users/me/go/bin/foo", false},
		"/Users/me/Downloads/foo":                 {"/Users/me/Downloads/foo", false},
		"/Users/me/.local/share/foo":              {"/Users/me/.local/share/foo", false},
		"/Users/me/Library/Application Support/x": {"/Users/me/Library/Application Support/x", false},
		"/Users/me/node_modules/.bin/x":           {"/Users/me/node_modules/.bin/x", false},
		"/tmp/x":                                  {"/tmp/x", false},
	} {
		target, dir := CommandTarget(real)
		if target != want.target || dir != want.dir {
			t.Errorf("%s: %s %v, ждали %s %v", real, target, dir, want.target, want.dir)
		}
	}
}
