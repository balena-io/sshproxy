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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

// Server holds server specific configuration data.
type Server struct {
	keyDir string
	config *ssh.ServerConfig
	shell  string
}

// New takes a directory to generate/store server keys, a path to the shell
// and an ssh.ServerConfig. If no ServerConfig is provided, then
// ServerConfig.NoClientAuth is set to true. ed25519 and rsa server keys
// and loaded, and generated if they do not exist. Returns a new Server.
func New(keyDir, shell string, sshConfig *ssh.ServerConfig) *Server {
	s := &Server{
		keyDir: keyDir,
		config: sshConfig,
		shell:  shell,
	}
	if s.config == nil {
		s.config = &ssh.ServerConfig{
			NoClientAuth: true,
		}
	}
	for _, keyType := range []string{"ed25519", "rsa"} {
		s.addHostKey(keyType)
	}

	return s
}

// Wraps ServerConfig.AddHostKey to create parent directories and keys if they do not already exist
func (s *Server) addHostKey(keyType string) {
	keyPath := filepath.Join(s.keyDir, fmt.Sprintf("id_%s", keyType))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// create keyPath parent directories
		os.MkdirAll(filepath.Dir(keyPath), os.ModePerm)
		// generate ssh server keys
		log.Printf("Generating private key... (%s)", keyType)
		err := exec.Command("ssh-keygen", "-f", keyPath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			panic(fmt.Sprintf("Failed to generate private key: %s\n%v", keyPath, err))
		}
	}

	log.Printf("Loading private key... (%s)", keyPath)
	raw, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to read private key: %s\n%v", keyPath, err))
	}
	pkey, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse private key: %s\n%v", keyPath, err))
	}

	s.config.AddHostKey(pkey)
}

// Listen for new ssh connections on the specified port.
func (s *Server) Listen(port string) {
	hostPort := net.JoinHostPort("0.0.0.0", port)
	listener, err := net.Listen("tcp", hostPort)
	if err != nil {
		panic(err)
	}
	log.Printf("Listening on ssh://%s\n", hostPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// TODO: handle failed connection
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
	for newChannel := range chans {
		log.Printf("New SSH channel from %s", conn.RemoteAddr())
		if chanType := newChannel.ChannelType(); chanType != "session" {
			newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Unsupported channel type: %s", chanType))
			continue
		}

		channel, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel request (%s)", err)
			continue
		}

		defer func() {
			channel.Close()
			log.Printf("Closed SSH channel with %s", conn.RemoteAddr())
		}()
		// Do not block handling requests so we can service new channels
		go s.handleRequests(reqs, channel, conn)
	}
}

// Service requests on given channel
func (s *Server) handleRequests(reqs <-chan *ssh.Request, channel ssh.Channel, conn *ssh.ServerConn) {
	env := make([]string, 0)
	wantsPty := false
	for req := range reqs {
		log.Printf("New SSH request '%s' from %s", req.Type, conn.RemoteAddr())
		switch req.Type {
		case "env":
			// append client env to the command environment
			keyLen := req.Payload[3]
			valLen := req.Payload[keyLen+7]
			key := string(req.Payload[4 : keyLen+4])
			val := string(req.Payload[keyLen+8 : keyLen+valLen+8])
			env = append(env, fmt.Sprintf("%s=%s", key, val))
			req.Reply(true, nil)
		case "pty-req":
			// client has requested a PTY
			wantsPty = true
			req.Reply(true, nil)
		case "shell":
			// client has not supplied a command, reject
			req.Reply(false, nil)
		case "exec":
			// setup is done, parse client exec command
			cmdLen := req.Payload[3]
			command := string(req.Payload[4 : cmdLen+4])
			req.Reply(true, nil)
			s.handleExec(conn, channel, command, env, wantsPty)
			log.Printf("Closing SSH channel with %s", conn.RemoteAddr())
			channel.Close()
			return
		default:
			log.Printf("Discarding request with unknown type '%s'", req.Type)
		}
	}
}

// Hand off to shell, creating PTY if requested
func (s *Server) handleExec(conn *ssh.ServerConn, channel ssh.Channel, command string, env []string, wantsPty bool) {
	log.Printf("Handling command '%s' from %s", command, conn.RemoteAddr())
	cmd := exec.Command(s.shell)
	cmd.Env = append(cmd.Env, env...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_USER=%s", conn.User()))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%s", command))

	if wantsPty {
		p, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go io.Copy(p, channel)
		io.Copy(channel, p)
	} else {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			panic(err)
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			panic(err)
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}

		if err = cmd.Start(); err != nil {
			panic(err)
		}

		go io.Copy(stdin, channel)
		go io.Copy(channel, stdout)
		go io.Copy(channel.Stderr(), stderr)

		cmd.Wait()
	}
	channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}
