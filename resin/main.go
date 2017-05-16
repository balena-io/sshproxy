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
	"bytes"
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/resin-io/pinejs-client-go"
	"github.com/resin-io/sshproxy"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type authHandler struct {
	baseURL, apiKey  string
	template         string
	rejectedSessions map[string]int
}

func newAuthHandler(baseURL, apiKey string) authHandler {
	return authHandler{
		baseURL:          baseURL,
		apiKey:           apiKey,
		template:         "",
		rejectedSessions: map[string]int{},
	}
}

func (a *authHandler) getUserKeys(username string) ([]ssh.PublicKey, error) {
	url := fmt.Sprintf("%s/%s", a.baseURL, "v1")
	client := pinejs.NewClient(url, a.apiKey)

	users := make([]map[string]interface{}, 1)
	users[0] = make(map[string]interface{})
	users[0]["pinejs"] = "user__has__public_key"

	filter := pinejs.QueryOption{
		Type: pinejs.Filter,
		Content: []string{fmt.Sprintf("user/any(u:((tolower(u/username)) eq ('%s')))",
			strings.ToLower(username))},
		Raw: true}
	fields := pinejs.QueryOption{
		Type:    pinejs.Select,
		Content: []string{"user", "public_key"},
	}
	if err := client.List(&users, filter, fields); err != nil {
		return nil, err
	} else if len(users) == 0 {
		return nil, errors.New("Invalid User")
	}

	keys := make([]ssh.PublicKey, 0)
	for _, user := range users {
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user["public_key"].(string))); err == nil {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (a *authHandler) publicKeyCallback(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	keys, err := a.getUserKeys(meta.User())
	if err != nil {
		return nil, errors.New("Unauthorised")
	}

	for _, k := range keys {
		if subtle.ConstantTimeCompare(k.Marshal(), key.Marshal()) == 1 {
			return nil, nil
		}
	}

	return nil, errors.New("Unauthorised")
}

func (a *authHandler) keyboardInteractiveCallback(meta ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// check if this session has already been rejected, only send the banner once
	sessionKey := string(meta.SessionID())
	if _, ok := a.rejectedSessions[sessionKey]; ok {
		// this operates on the assumption that `keyboard-interactive` will be attempted three times
		// and then cleans up the state
		a.rejectedSessions[sessionKey]++
		if a.rejectedSessions[sessionKey] == 3 {
			delete(a.rejectedSessions, sessionKey)
		}
		return nil, errors.New("Unauthorised")
	} else {
		a.rejectedSessions[sessionKey] = 1
	}

	// fetch user's keys...
	keys, err := a.getUserKeys(meta.User())
	if err != nil {
		return nil, errors.New("Unauthorised")
	}
	// ...and generate their fingerprints
	fingerprints := make([]string, 0)
	for _, key := range keys {
		hash := md5.New()
		hash.Write(key.Marshal())
		fingerprint := fmt.Sprintf("%x", hash.Sum(nil))
		fingerprints = append(fingerprints, fingerprint)
	}

	tmpl := template.Must(template.New("auth_failed_template").Parse(a.template))
	msg := bytes.NewBuffer(nil)
	// pass `user` and `fingerprints` vars to template and render
	tmpl.Execute(msg, map[string]interface{}{"user": meta.User(), "fingerprints": fingerprints})

	// send the rendered template as an auth challenge with no questions
	client(meta.User(), msg.String(), nil, nil)
	return nil, errors.New("Unauthorised")
}

func init() {
	pflag.CommandLine.StringP("apihost", "H", "api.resin.io", "Resin API Host")
	pflag.CommandLine.StringP("apiport", "P", "443", "Resin API Port")
	pflag.CommandLine.StringP("apikey", "K", "", "Resin API Key (required)")
	pflag.CommandLine.StringP("dir", "d", "/etc/sshproxy", "Work dir, holds ssh keys and sshproxy config")
	pflag.CommandLine.IntP("port", "p", 22, "Port the ssh service will listen on")
	pflag.CommandLine.StringP("shell", "s", "shell.sh", "Path to shell to execute post-authentication")
	pflag.CommandLine.StringP("auth-failed-banner", "b", "", "Path to template displayed after failed authentication")
	pflag.CommandLine.IntP("max-auth-tries", "m", 0, "Maximum number of authentication attempts per connection (default 0; unlimited)")

	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("sshproxy")
	viper.SetEnvPrefix("SSHPROXY")
	viper.BindEnv("apihost", "RESIN_API_HOST")
	viper.BindEnv("apiport", "RESIN_API_PORT")
	viper.BindEnv("apikey", "SSHPROXY_API_KEY")
	viper.BindEnv("dir")
	viper.BindEnv("port")
	viper.BindEnv("shell")
	viper.BindEnv("auth-failed-banner", "SSHPROXY_AUTH_FAILED_BANNER")
	viper.BindEnv("max-auth-tries", "SSHPROXY_MAX_AUTH_TRIES")
}

func main() {
	log.SetFlags(0)
	pflag.Parse()
	viper.AddConfigPath(viper.GetString("dir"))
	viper.AddConfigPath("/etc")
	viper.ReadInConfig()

	// API Key is required
	if !viper.IsSet("apikey") || viper.GetString("apikey") == "" {
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
	fix_path_check_exists := func(key string) {
		if viper.GetString(key)[0] != '/' {
			viper.Set(key, path.Join(viper.GetString("dir"), viper.GetString(key)))
		}
		if _, err := os.Stat(viper.GetString(key)); err != nil {
			fmt.Fprintf(os.Stderr, "%s: No such file or directory\n", viper.Get(key))
			os.Exit(2)
		}
	}
	fix_path_check_exists("shell")
	if viper.IsSet("auth-failed-banner") {
		fix_path_check_exists("auth-failed-banner")
	}

	apiURL := fmt.Sprintf("https://%s:%d", viper.GetString("apihost"), viper.GetInt("apiport"))
	auth := newAuthHandler(apiURL, viper.GetString("apikey"))
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: auth.publicKeyCallback,
		MaxAuthTries:      viper.GetInt("max-auth-tries"),
	}
	if viper.IsSet("auth-failed-banner") {
		tmpl, err := ioutil.ReadFile(viper.GetString("auth-failed-banner"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(2)
		}
		auth.template = string(tmpl)
		sshConfig.KeyboardInteractiveCallback = auth.keyboardInteractiveCallback
	}

	sshproxy.New(viper.GetString("dir"), viper.GetString("shell"), sshConfig).Listen(viper.GetString("port"))
}
