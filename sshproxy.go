/*
Copyright 2017 Resin.io

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

// Package sshproxy is a simple ssh server library exposing an even simpler API.
// Authentication is handled by providing a ServerConfig, allowing full customisation.
// After authentication control is handed to the specified shell executable, with a PTY
// if requested by the connecting client.
package sshproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/resin-io-modules/gexpect/pty"
	"golang.org/x/crypto/ssh"
)

// Server holds server specific configuration data.
type Server struct {
	keyDir       string
	config       *ssh.ServerConfig
	shell        string
	shellCreds   *syscall.Credential
	passEnv      bool
	errorHandler ErrorHandler
}

// ErrorHandler is passed any non-fatal errors for reporting.
type ErrorHandler func(error, map[string]string)

// New takes a directory to generate/store server keys, a path to the shell
// and an ssh.ServerConfig. If no ServerConfig is provided, then
// ServerConfig.NoClientAuth is set to true. ed25519, rsa, ecdsa and dsa
// keys are loaded, and generated if they do not exist. Returns a new Server.
func New(keyDir, shell string, passEnv bool, shellCreds *syscall.Credential, sshConfig *ssh.ServerConfig, errorHandler ErrorHandler) (*Server, error) {
	s := &Server{
		keyDir:       keyDir,
		config:       sshConfig,
		shell:        shell,
		shellCreds:   shellCreds,
		passEnv:      passEnv,
		errorHandler: errorHandler,
	}
	if s.config == nil {
		s.config = &ssh.ServerConfig{
			NoClientAuth: true,
		}
	}
	for _, keyType := range []string{"ed25519", "rsa", "ecdsa", "dsa"} {
		if err := s.addHostKey(keyType); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Server) handleError(err error, tags map[string]string) {
	if s.errorHandler != nil {
		s.errorHandler(err, tags)
	}
}

// Wraps ServerConfig.AddHostKey to create parent directories and keys if they do not already exist
func (s *Server) addHostKey(keyType string) error {
	keyPath := filepath.Join(s.keyDir, fmt.Sprintf("id_%s", keyType))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// create keyPath parent directories
		if err := os.MkdirAll(filepath.Dir(keyPath), os.ModePerm); err != nil {
			return err
		}
		// generate ssh server keys
		log.Printf("Generating private key... (%s)", keyType)
		err := exec.Command("ssh-keygen", "-f", keyPath, "-t", keyType, "-N", "").Run()
		if err != nil {
			return err
		}
	}

	log.Printf("Loading private key... (%s)", keyPath)
	raw, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	pkey, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return err
	}

	s.config.AddHostKey(pkey)
	return nil
}

// Listen for new ssh connections on the specified port.
func (s *Server) Listen(port string) error {
	hostPort := net.JoinHostPort("0.0.0.0", port)
	listener, err := net.Listen("tcp", hostPort)
	if err != nil {
		return err
	}
	log.Printf("Listening on ssh://%s\n", hostPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		log.Printf("New TCP connection from %s", conn.RemoteAddr())

		go s.upgradeConnection(conn)
	}
}

// Attempts to perform SSH handshake on new TCP connections
func (s *Server) upgradeConnection(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		log.Printf("Handshake with %s failed (%s)", conn.RemoteAddr(), err)
		return
	}
	log.Printf("New SSH connection from %s (%s)", conn.RemoteAddr(), sshConn.ClientVersion())

	defer func() {
		conn.Close()
		log.Printf("Closed connection to %s", conn.RemoteAddr())
	}()
	go ssh.DiscardRequests(reqs)
	s.handleChannels(chans, sshConn)
}

// After successful handshake, handle new channels. Only the "session" type is supported.
func (s *Server) handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
	var wg sync.WaitGroup
	for newChannel := range chans {
		log.Printf("New SSH channel from %s", conn.RemoteAddr())
		if chanType := newChannel.ChannelType(); chanType != "session" {
			if err := newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Unsupported channel type: %s", chanType)); err != nil {
				s.handleError(err, nil)
			}
			continue
		}

		channel, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel request (%s)", err)
			continue
		}

		// Do not block handling requests so we can service new channels
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.handleRequests(reqs, channel, conn); err != nil {
				s.handleError(err, nil)
			}
		}()
	}
	wg.Wait()
}

// Service requests on given channel
func (s *Server) handleRequests(reqs <-chan *ssh.Request, channel ssh.Channel, conn *ssh.ServerConn) error {
	env := make([]string, 0)
	var terminal *pty.Terminal
	var cmd *exec.Cmd

	for req := range reqs {
		switch req.Type {
		case "env":
			if s.passEnv {
				// append client env to the command environment
				keyLen := req.Payload[3]
				valLen := req.Payload[keyLen+7]
				key := string(req.Payload[4 : keyLen+4])
				val := string(req.Payload[keyLen+8 : keyLen+valLen+8])
				env = append(env, fmt.Sprintf("%s=%s", key, val))
			}
			if err := req.Reply(s.passEnv, nil); err != nil {
				return err
			}
		case "pty-req":
			if terminal == nil {
				var err error
				terminal, err = pty.NewTerminal()
				if err != nil {
					return err
				}

				termLen := req.Payload[3]
				term := req.Payload[4 : termLen+4]
				env = append(env, fmt.Sprintf("TERM=%s", term))
				w := int(binary.BigEndian.Uint32(req.Payload[termLen+4 : termLen+8]))
				h := int(binary.BigEndian.Uint32(req.Payload[termLen+8 : termLen+12]))
				if err := terminal.SetWinSize(w, h); err != nil {
					return err
				}
			}
			if err := req.Reply(terminal != nil, nil); err != nil {
				return err
			}
		case "window-change":
			if terminal != nil {
				w := int(binary.BigEndian.Uint32(req.Payload[0:4]))
				h := int(binary.BigEndian.Uint32(req.Payload[4:8]))
				if err := terminal.SetWinSize(w, h); err != nil {
					return err
				}
			}
		case "exec":
			// setup is done, parse client exec command
			cmdLen := req.Payload[3]
			command := string(req.Payload[4 : cmdLen+4])
			log.Printf("Handling command '%s' from %s", command, conn.RemoteAddr())
			cmd = exec.Command(s.shell)
			cmd.Env = append(cmd.Env, env...)
			cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_USER=%s", conn.User()))
			cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%s", command))

			if err := s.launchCommand(channel, cmd, terminal); err != nil {
				s.handleError(err, nil)
			}

			if req.WantReply {
				if err := req.Reply(true, nil); err != nil {
					return err
				}
			}

			go func() {
				done := make(chan error, 1)
				go func() {
					done <- cmd.Wait()
				}()
			Loop:
				for {
					select {
					case <-time.After(10 * time.Second):
						if _, err := channel.SendRequest("ping", false, []byte{}); err != nil {
							// Channel is dead, kill process
							if err := cmd.Process.Kill(); err != nil {
								s.handleError(err, nil)
							}
							break Loop
						}
					case <-done:
						break Loop
					}
				}

				exitStatusPayload := make([]byte, 4)
				exitStatus := uint32(1)
				if cmd.ProcessState != nil {
					if sysProcState := cmd.ProcessState.Sys(); sysProcState != nil {
						if cmdWaitStatus, ok := sysProcState.(syscall.WaitStatus); ok {
							exitStatus = uint32(cmdWaitStatus.ExitStatus())
						}
					}
				}
				binary.BigEndian.PutUint32(exitStatusPayload, uint32(exitStatus))
				if _, err := channel.SendRequest("exit-status", false, exitStatusPayload); err != nil {
					s.handleError(err, nil)
				}

				if terminal != nil {
					if err := terminal.Close(); err != nil {
						s.handleError(err, nil)
					}
				}
				if err := channel.Close(); err != nil {
					s.handleError(err, nil)
				}
				log.Printf("Closed SSH channel with %s", conn.RemoteAddr())
			}()

		default:
			log.Printf("Discarding request with unknown type '%s'", req.Type)
			if req.WantReply {
				if err := req.Reply(false, nil); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (s *Server) launchCommand(channel ssh.Channel, cmd *exec.Cmd, terminal *pty.Terminal) error {
	if s.shellCreds != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: s.shellCreds}
	}

	if terminal != nil {
		err := terminal.Start(cmd)
		if err != nil {
			return err
		}

		go io.Copy(terminal, channel)
		go io.Copy(channel, terminal)
	} else {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		if err = cmd.Start(); err != nil {
			return err
		}

		go io.Copy(stdin, channel)
		go io.Copy(channel, stdout)
		go io.Copy(channel.Stderr(), stderr)
	}

	return nil
}
