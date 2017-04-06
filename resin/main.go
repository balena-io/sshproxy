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
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/resin-io/pinejs-client-go"
	"github.com/resin-io/sshproxy"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func authHandler(baseURL, apiKey string) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	url := fmt.Sprintf("%s/%s", baseURL, "ewa")
	client := pinejs.NewClient(url, apiKey)

	handler := func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		users := make([]map[string]interface{}, 1)
		users[0] = make(map[string]interface{})
		users[0]["pinejs"] = "user__has__public_key"

		filter := pinejs.QueryOption{
			Type: pinejs.Filter,
			Content: []string{fmt.Sprintf("user/any(u:((tolower(u/username)) eq ('%s')))",
				strings.ToLower(meta.User()))},
			Raw: true}
		fields := pinejs.QueryOption{
			Type:    pinejs.Select,
			Content: []string{"user", "public_key"},
		}
		if err := client.List(&users, filter, fields); err != nil {
			return nil, err
		} else if len(users) == 0 {
			return nil, errors.New("Unauthorised")
		}

		for _, user := range users {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user["public_key"].(string)))
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare(k.Marshal(), key.Marshal()) == 1 {
				return nil, nil
			}
		}

		return nil, errors.New("Unauthorised")
	}

	return handler
}

func init() {
	pflag.CommandLine.StringP("apihost", "H", "api.resin.io", "Resin API Host")
	pflag.CommandLine.StringP("apiport", "P", "443", "Resin API Port")
	pflag.CommandLine.StringP("apikey", "K", "", "Resin API Key (required)")
	pflag.CommandLine.StringP("dir", "d", "/etc/sshproxy", "Work dir, holds ssh keys and sshproxy config")
	pflag.CommandLine.IntP("port", "p", 22, "Port the ssh service will listen on")
	pflag.CommandLine.StringP("shell", "s", "shell.sh", "Path to shell to execute post-authentication")

	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("sshproxy")
	viper.SetEnvPrefix("SSHPROXY")
	viper.BindEnv("apihost", "RESIN_API_HOST")
	viper.BindEnv("apiport", "RESIN_API_PORT")
	viper.BindEnv("apikey", "SSHPROXY_API_KEY")
	viper.BindEnv("dir")
	viper.BindEnv("port")
	viper.BindEnv("shell")
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

	// if shell is relative, prepend with dir
	if viper.Get("shell").(string)[0] != '/' {
		viper.Set("shell", path.Join(viper.GetString("dir"), viper.GetString("shell")))
	}
	if _, err := os.Stat(viper.GetString("shell")); err != nil {
		fmt.Fprintf(os.Stderr, "%s: No such file or directory\n", viper.Get("shell"))
		os.Exit(2)
	}

	apiURL := fmt.Sprintf("https://%s:%d", viper.GetString("apihost"), viper.GetInt("apiport"))
	sshConfig := &ssh.ServerConfig{PublicKeyCallback: authHandler(apiURL, viper.GetString("apikey"))}
	sshproxy.New(viper.GetString("dir"), viper.GetString("shell"), sshConfig).Listen(viper.GetString("port"))
}
