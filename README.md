# sshproxy

[![GoDoc](https://godoc.org/github.com/resin-io/sshproxy?status.svg)](https://godoc.org/github.com/resin-io/sshproxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/resin-io/sshproxy)](https://goreportcard.com/report/github.com/resin-io/sshproxy)

sshproxy is a simple ssh server library exposing an even simpler API.
Authentication is handled by providing a ServerConfig, allowing full customisation.
After authentication control is handed to the specified shell executable, with a PTY
if requested by the connecting client.
