package sshproxy_test

import (
	"net"
	"testing"
	"time"

	"github.com/balena-io/sshproxy"
	"golang.org/x/crypto/ssh"
)

func TestRace(t *testing.T) {
	server, err := sshproxy.New(
		"/tmp",
		"/bin/bash",
		false,
		nil,
		3,
		nil,
		func(err error, tags map[string]string) {
			t.Logf("uncaught error: %s", err)
		})

	if err != nil {
		t.Fatalf("error calling sshproxy.New :( %s", err)
	}

	go func() {
		if err := server.Listen("12345"); err != nil {
			t.Fatalf("Cannot start server! %s", err)
		}
	}()

	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	for i := 0; i < 10; i++ {
		client, err := ssh.Dial("tcp", "localhost:12345", config)
		if err != nil {
			t.Errorf("Cannot connect to server :( %s", err)
		}
		session, err := client.NewSession()
		if err != nil {
			t.Errorf("Cannot create session :( %s", err)
		}
		time.Sleep(time.Second)
		_, err = session.SendRequest("exec", false, []byte{0, 0, 0, 4, 't', 'e', 's', 't'})
		if err != nil {
			t.Errorf("Cannot send exec request :( %q", err)
		}
		time.Sleep(time.Duration(i*100) * time.Millisecond)
		if err := client.Close(); err != nil {
			t.Errorf("Error closing client - %s", err)
		}
	}
}
