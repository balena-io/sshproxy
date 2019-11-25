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

// See https://github.com/balena-io/sshproxy#readme
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	raven "github.com/getsentry/raven-go"
	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	gossh "golang.org/x/crypto/ssh"
)

var version string

func init() {
	pflag.CommandLine.StringP("apihost", "H", "api.balena-cloud.com", "Balena API Host")
	pflag.CommandLine.StringP("apiport", "P", "443", "Balena API Port")
	pflag.CommandLine.StringP("apikey", "K", "", "Balena API Key (required)")
	pflag.CommandLine.StringP("dir", "d", "/etc/sshproxy", "Work dir, holds ssh keys and sshproxy config")
	pflag.CommandLine.StringP("bind", "b", ":22", "Address the ssh service will bind to")
	pflag.CommandLine.StringP("shell", "s", "shell.sh", "Path to shell to execute post-authentication")
	pflag.CommandLine.Int64P("shell-uid", "u", -1, "User to run shell as (default: current uid)")
	pflag.CommandLine.Int64P("shell-gid", "g", -1, "Group to run shell as (default: current gid)")
	pflag.CommandLine.IntP("idle-timeout", "i", 0, "Idle timeout (seconds, 0 = none)")
	pflag.CommandLine.StringP("auth-failed-banner", "B", "", "Path to template displayed after failed authentication")
	pflag.CommandLine.IntP("max-auth-tries", "m", 0, "Maximum number of authentication attempts per connection (default 0; unlimited)")
	pflag.CommandLine.StringP("allow-env", "E", "", "List of environment variables to pass from client to shell (default: None)")
	pflag.CommandLine.StringP("metrics-bind", "M", "", "Address the prometheus metrics server should bind to (default: disabled)")
	pflag.CommandLine.StringP("sentry-dsn", "S", "", "Sentry DSN for error reporting")
	pflag.CommandLine.IntP("verbosity", "v", 1, "Set verbosity level (0 = quiet, 1 = normal, 2 = verbose, 3 = debug, default: 1)")
	pflag.CommandLine.BoolP("version", "", false, "Display version and exit")

	viper.SetConfigName("sshproxy")
	viper.SetEnvPrefix("SSHPROXY")
	err := func() error {
		if err := viper.BindPFlags(pflag.CommandLine); err != nil {
			return err
		}
		if err := viper.BindEnv("apihost", "BALENA_API_HOST"); err != nil {
			return err
		}
		if err := viper.BindEnv("apiport", "BALENA_API_PORT"); err != nil {
			return err
		}
		if err := viper.BindEnv("apikey", "SSHPROXY_API_KEY"); err != nil {
			return err
		}
		if err := viper.BindEnv("dir"); err != nil {
			return err
		}
		if err := viper.BindEnv("bind"); err != nil {
			return err
		}
		if err := viper.BindEnv("shell"); err != nil {
			return err
		}
		if err := viper.BindEnv("verbosity"); err != nil {
			return err
		}
		if err := viper.BindEnv("shell-uid", "SSHPROXY_SHELL_UID"); err != nil {
			return err
		}
		if err := viper.BindEnv("shell-gid", "SSHPROXY_SHELL_GID"); err != nil {
			return err
		}
		if err := viper.BindEnv("auth-failed-banner", "SSHPROXY_AUTH_FAILED_BANNER"); err != nil {
			return err
		}
		if err := viper.BindEnv("max-auth-tries", "SSHPROXY_MAX_AUTH_TRIES"); err != nil {
			return err
		}
		if err := viper.BindEnv("allow-env", "SSHPROXY_ALLOW_ENV"); err != nil {
			return err
		}
		if err := viper.BindEnv("metrics-bind", "SSHPROXY_METRICS_BIND"); err != nil {
			return err
		}
		if err := viper.BindEnv("sentry-dsn", "SSHPROXY_SENTRY_DSN"); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		log.Fatal("Initialisation failed", err)
	}
}

func main() {
	log.SetFlags(0)
	pflag.Parse()
	viper.AddConfigPath(viper.GetString("dir"))
	viper.AddConfigPath("/etc")
	_ = viper.ReadInConfig()

	if viper.GetBool("version") {
		fmt.Printf("sshproxy %s (%s)\n", version, runtime.Version())
		return
	}

	// API Key is required
	if viper.GetString("apikey") == "" {
		fmt.Fprintln(os.Stderr, "Error: Balena API Key is required.")
		pflag.Usage()
		os.Exit(2)
	}

	// `dir` path must be absolute
	if viper.GetString("dir")[0] != '/' {
		fmt.Fprintln(os.Stderr, "Error: dir must be absolute.")
		os.Exit(2)
	}

	// if paths are relative, prepend with dir and verify files exist
	fixPathCheckExists := func(key string) {
		if viper.GetString(key)[0] != '/' {
			viper.Set(key, path.Join(viper.GetString("dir"), viper.GetString(key)))
		}
		if _, err := os.Stat(viper.GetString(key)); err != nil {
			fmt.Fprintf(os.Stderr, "%s: No such file or directory\n", viper.Get(key))
			os.Exit(2)
		}
	}
	fixPathCheckExists("shell")
	if viper.GetString("auth-failed-banner") != "" {
		fixPathCheckExists("auth-failed-banner")
	}

	shellCreds := &syscall.Credential{}
	if viper.GetInt64("shell-uid") > 0 {
		shellCreds.Uid = uint32(viper.GetInt64("shell-uid"))
	}
	if viper.GetInt64("shell-gid") > 0 {
		shellCreds.Gid = uint32(viper.GetInt64("shell-gid"))
	}

	apiURL := fmt.Sprintf("https://%s:%d", viper.GetString("apihost"), viper.GetInt("apiport"))

	if viper.GetString("sentry-dsn") != "" {
		if err := raven.SetDSN(viper.GetString("sentry-dsn")); err != nil {
			log.Fatal("Sentry initialisation failed", err)
		}
	}

	verbosity := viper.GetInt("verbosity")
	auth := newAuthHandler(apiURL, viper.GetString("apikey"))
	sshConfig := &gossh.ServerConfig{
		MaxAuthTries: viper.GetInt("max-auth-tries"),
	}
	server := ssh.Server{
		Addr:                 viper.GetString("bind"),
		PublicKeyHandler:     auth.publicKeyHandler,
		ServerConfigCallback: func(session ssh.Context) *gossh.ServerConfig { return sshConfig },
	}
	if viper.GetInt("idle-timeout") > 0 {
		server.IdleTimeout = time.Duration(viper.GetInt("idle-timeout"))
	}
	for _, keyType := range []string{"ed25519", "rsa", "ecdsa", "dsa"} {
		if err := addHostKey(&server, viper.GetString("dir"), keyType); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(2)
		}
	}
	if viper.GetString("auth-failed-banner") != "" {
		tmpl, err := ioutil.ReadFile(viper.GetString("auth-failed-banner"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(2)
		}
		auth.template = string(tmpl)
		server.KeyboardInteractiveHandler = auth.keyboardInteractiveHandler
	}

	server.ConnCallback = func(ctx ssh.Context, conn net.Conn) net.Conn {
		if verbosity >= 2 {
			log.Printf("inbound connection from %s", conn.RemoteAddr())
		}
		remoteAddrParts := strings.Split(conn.RemoteAddr().String(), ":")
		ip := strings.Join(remoteAddrParts[0:len(remoteAddrParts)-1], ":")
		totalConnections.With(prometheus.Labels{"ip": ip}).Inc()
		return conn
	}

	server.Handle(makeHandler(
		viper.GetString("shell"),
		shellCreds,
		strings.Split(viper.GetString("allow-env"), ","),
		verbosity,
	))

	if metricsBind := viper.GetString("metrics-bind"); metricsBind != "" {
		if verbosity >= 1 {
			log.Printf("starting metrics server on %s", metricsBind)
		}
		go serveMetrics(metricsBind)
	}

	if verbosity >= 1 {
		log.Printf("starting ssh server on %s", viper.GetString("bind"))
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}
