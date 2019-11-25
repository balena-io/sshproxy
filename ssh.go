/*
Copyright 2017 Balena Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/balena-io-modules/gexpect/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func addHostKey(s *ssh.Server, dir string, keyType string) error {
	keyPath := filepath.Join(dir, fmt.Sprintf("id_%s", keyType))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(keyPath), os.ModePerm); err != nil {
			return err
		}
		err := exec.Command("ssh-keygen", "-f", keyPath, "-t", keyType, "-N", "", "-m", "PEM").Run()
		if err != nil {
			return err
		}
	}

	raw, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	pkey, err := gossh.ParsePrivateKey(raw)
	if err != nil {
		return err
	}

	s.AddHostKey(pkey)
	return nil
}

func makeHandler(
	shell string,
	creds *syscall.Credential,
	envKeysWhitelist []string,
	verbosity int,
) ssh.Handler {
	return func(session ssh.Session) {
		log.Printf("Handling command '%s' from %s@%s", session.RawCommand(), session.User(), session.RemoteAddr())

		cmd := exec.Command(shell)
		if creds != nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: creds}
		}

		activeSessions.Inc()
		totalSessions.Inc()
		defer activeSessions.Dec()

		if len(envKeysWhitelist) > 0 {
			envWhitelist := make(map[string]bool)
			for _, key := range envKeysWhitelist {
				envWhitelist[key] = true
			}
			for _, env := range session.Environ() {
				key := strings.Split(env, "=")[0]
				if envWhitelist[key] {
					cmd.Env = append(cmd.Env, env)
				}
			}
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_USER=%s", session.User()))
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%s", session.RawCommand()))

		if ptqReq, winCh, isPty := session.Pty(); isPty {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptqReq.Term))
			terminal, err := pty.Start(cmd)
			if err != nil {
				return
			}
			go func() {
				for win := range winCh {
					terminal.SetWinSize(win.Width, win.Height)
				}
			}()

			go io.Copy(terminal, session)
			go io.Copy(session, terminal)
		} else {
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return
			}

			stderr, err := cmd.StderrPipe()
			if err != nil {
				return
			}

			stdin, err := cmd.StdinPipe()
			if err != nil {
				return
			}

			if err := cmd.Start(); err != nil {
				return
			}

			go io.Copy(stdin, session)
			go io.Copy(session, stdout)
			go io.Copy(session.Stderr(), stderr)
		}
		cmd.Wait()
	}
}
