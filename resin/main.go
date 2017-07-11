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

// A "resin-ready" binary which handles authentication via resin api,
// requiring minimal configuration.
//
// See https://github.com/resin-io/sshproxy/tree/master/resin#readme
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"syscall"

	"github.com/getsentry/raven-go"
	"github.com/resin-io/sshproxy"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

var version string

func init() {
	pflag.CommandLine.StringP("apihost", "H", "api.resin.io", "Resin API Host")
	pflag.CommandLine.StringP("apiport", "P", "443", "Resin API Port")
	pflag.CommandLine.StringP("apikey", "K", "", "Resin API Key (required)")
	pflag.CommandLine.StringP("dir", "d", "/etc/sshproxy", "Work dir, holds ssh keys and sshproxy config")
	pflag.CommandLine.IntP("port", "p", 22, "Port the ssh service will listen on")
	pflag.CommandLine.StringP("shell", "s", "shell.sh", "Path to shell to execute post-authentication")
	pflag.CommandLine.Int64P("shell-uid", "u", -1, "User to run shell as (default: current uid)")
	pflag.CommandLine.Int64P("shell-gid", "g", -1, "Group to run shell as (default: current gid)")
	pflag.CommandLine.StringP("auth-failed-banner", "b", "", "Path to template displayed after failed authentication")
	pflag.CommandLine.IntP("max-auth-tries", "m", 0, "Maximum number of authentication attempts per connection (default 0; unlimited)")
	pflag.CommandLine.BoolP("allow-env", "E", false, "Pass environment from client to shell (default: false) (warning: security implications)")
	pflag.CommandLine.StringP("sentry-dsn", "S", "", "Sentry DSN for error reporting")
	pflag.CommandLine.BoolP("version", "", false, "Display version and exit")

	viper.SetConfigName("sshproxy")
	viper.SetEnvPrefix("SSHPROXY")
	err := func() error {
		if err := viper.BindPFlags(pflag.CommandLine); err != nil {
			return err
		}
		if err := viper.BindEnv("apihost", "RESIN_API_HOST"); err != nil {
			return err
		}
		if err := viper.BindEnv("apiport", "RESIN_API_PORT"); err != nil {
			return err
		}
		if err := viper.BindEnv("apikey", "SSHPROXY_API_KEY"); err != nil {
			return err
		}
		if err := viper.BindEnv("dir"); err != nil {
			return err
		}
		if err := viper.BindEnv("port"); err != nil {
			return err
		}
		if err := viper.BindEnv("shell"); err != nil {
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
		fmt.Fprintln(os.Stderr, "Error: Resin API Key is required.")
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
	auth := newAuthHandler(apiURL, viper.GetString("apikey"))
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: auth.publicKeyCallback,
		MaxAuthTries:      viper.GetInt("max-auth-tries"),
	}
	if viper.GetString("auth-failed-banner") != "" {
		tmpl, err := ioutil.ReadFile(viper.GetString("auth-failed-banner"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(2)
		}
		auth.template = string(tmpl)
		sshConfig.KeyboardInteractiveCallback = auth.keyboardInteractiveCallback
	}

	if viper.GetString("sentry-dsn") != "" {
		if err := raven.SetDSN(viper.GetString("sentry-dsn")); err != nil {
			log.Fatal("Sentry initialisation failed", err)
		}
	}

	server, err := sshproxy.New(
		viper.GetString("dir"),
		viper.GetString("shell"),
		viper.GetBool("allow-env"),
		shellCreds,
		sshConfig,
		func(err error, tags map[string]string) {
			log.Printf("ERROR: %s", err)
			raven.CaptureError(err, tags)
		})
	if err != nil {
		log.Fatal("Error creating Server instance", err)
	}
	if err := server.Listen(viper.GetString("port")); err != nil {
		log.Fatal("Error binding to port", err)
	}
}
