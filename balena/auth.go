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
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"text/template"

	pinejs "github.com/balena-io/pinejs-client-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/syncmap"
)

type authHandler struct {
	baseURL, apiKey  string
	template         string
	rejectedSessions syncmap.Map
}

func parseInt(i interface{}) (int, error) {
	n, ok := i.(int)
	if !ok {
		return 0, errors.New("invalid number")
	}
	return n, nil
}

func newAuthHandler(baseURL, apiKey string) authHandler {
	return authHandler{
		baseURL:          baseURL,
		apiKey:           apiKey,
		template:         "",
		rejectedSessions: syncmap.Map{},
	}
}

func (a *authHandler) getUserKeys(username string) ([]ssh.PublicKey, error) {
	url := fmt.Sprintf("%s/%s", a.baseURL, "v5")
	client := pinejs.NewClient(url, a.apiKey)

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
	if i, ok := a.rejectedSessions.Load(sessionKey); ok {
		n, err := parseInt(i)
		if err != nil {
			return nil, errors.New("Unauthorised")
		}
		// this operates on the assumption that `keyboard-interactive` will be attempted three times
		// and then cleans up the state
		if n == 3 {
			a.rejectedSessions.Delete(sessionKey)
		} else {
			a.rejectedSessions.Store(sessionKey, n+1)
		}
		return nil, errors.New("Unauthorised")
	}
	a.rejectedSessions.Store(sessionKey, 1)

	// fetch user's keys...
	keys, err := a.getUserKeys(meta.User())
	if err != nil {
		return nil, errors.New("Unauthorised")
	}
	// ...and generate their fingerprints
	fingerprints := make([]string, 0)
	for _, key := range keys {
		hash := md5.New()
		if _, err := hash.Write(key.Marshal()); err != nil {
			return nil, err
		}
		fingerprint := fmt.Sprintf("%x", hash.Sum(nil))
		fingerprints = append(fingerprints, fingerprint)
	}

	tmpl := template.Must(template.New("auth_failed_template").Parse(a.template))
	msg := bytes.NewBuffer(nil)
	// pass `user` and `fingerprints` vars to template and render
	if err := tmpl.Execute(msg, map[string]interface{}{"user": meta.User(), "fingerprints": fingerprints}); err != nil {
		return nil, err
	}

	// send the rendered template as an auth challenge with no questions
	if _, err := client(meta.User(), msg.String(), nil, nil); err != nil {
		return nil, err
	}

	return nil, errors.New("Unauthorised")
}
