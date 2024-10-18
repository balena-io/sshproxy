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
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"strings"
	"text/template"

	pinejs "github.com/balena-io/pinejs-client-go"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type authHandler struct {
	baseURL, apiKey  string
	template         string
	rejectedSessions map[string]int
	verbosity        int
}

func newAuthHandler(baseURL, apiKey string, verbosity int) authHandler {
	return authHandler{
		baseURL:          baseURL,
		apiKey:           apiKey,
		template:         "",
		rejectedSessions: map[string]int{},
		verbosity:        verbosity,
	}
}

func (a *authHandler) getUserKeys(username string) ([]gossh.PublicKey, error) {
	url := fmt.Sprintf("%s/%s", a.baseURL, "v7")
	client := pinejs.NewClientWithToken(url, a.apiKey)

	users := make([]map[string]interface{}, 1)
	users[0] = make(map[string]interface{})
	users[0]["pinejs"] = "user__has__public_key"

	filter := pinejs.QueryOption{
		Type: pinejs.Filter,
		Content: []string{fmt.Sprintf("user/any(u:tolower(u/username) eq '%s')",
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

	keys := make([]gossh.PublicKey, 0)
	for _, user := range users {
		if key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(user["public_key"].(string))); err == nil {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (a *authHandler) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	keys, err := a.getUserKeys(ctx.User())
	if err != nil {
		return false
	}

	for _, k := range keys {
		if ssh.KeysEqual(k, key) {
			return true
		}
	}

	if a.verbosity >= 3 {
		log.Printf("public key auth failed for %s@%s", ctx.User(), ctx.RemoteAddr().String())
	}

	return false
}

func (a *authHandler) keyboardInteractiveHandler(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
	// check if this session has already been rejected, only send the banner once
	sessionKey := string(ctx.SessionID())
	if _, ok := a.rejectedSessions[sessionKey]; ok {
		// this operates on the assumption that `keyboard-interactive` will be attempted three times
		// and then cleans up the state
		a.rejectedSessions[sessionKey]++
		if a.rejectedSessions[sessionKey] == 3 {
			delete(a.rejectedSessions, sessionKey)
		}
		return false
	}
	a.rejectedSessions[sessionKey] = 1

	if a.verbosity >= 3 {
		log.Printf("keyboard interactive auth failed for %s@%s", ctx.User(), ctx.RemoteAddr().String())
	}

	// fetch user's keys...
	keys, err := a.getUserKeys(ctx.User())
	if err != nil {
		return false
	}
	// ...and generate their fingerprints
	fingerprints := make([]string, 0)
	for _, key := range keys {
		hash := md5.New()
		if _, err := hash.Write(key.Marshal()); err != nil {
			return false
		}
		fingerprint := fmt.Sprintf("%x", hash.Sum(nil))
		fingerprints = append(fingerprints, fingerprint)
	}

	tmpl := template.Must(template.New("auth_failed_template").Parse(a.template))
	msg := bytes.NewBuffer(nil)
	// pass `user` and `fingerprints` vars to template and render
	if err := tmpl.Execute(msg, map[string]interface{}{"user": ctx.User(), "fingerprints": fingerprints}); err != nil {
		return false
	}

	// send the rendered template as an auth challenge with no questions
	if _, err := challenger(ctx.User(), msg.String(), nil, nil); err != nil {
		return false
	}

	return false
}
