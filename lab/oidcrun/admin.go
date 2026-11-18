package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

const adminBase = "http://127.0.0.1:8080/admin/realms/ssotrace-lab"

// admin changes the lab realm through Keycloak's admin REST API: the same
// settings the lab README tells a person to change in the admin console.
// Its traffic is never recorded; it is the operator, not the user.
type admin struct {
	client *http.Client
	token  string
}

func newAdmin(user, password string) (*admin, error) {
	a := &admin{client: &http.Client{Timeout: 20 * time.Second}}
	resp, err := a.client.PostForm("http://127.0.0.1:8080/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {user},
		"password":   {password},
	})
	if err != nil {
		return nil, fmt.Errorf("admin sign-in: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin sign-in: HTTP %d (check KC_BOOTSTRAP_ADMIN_* in lab/.env)", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("admin sign-in: %w", err)
	}
	a.token = tok.AccessToken
	return a, nil
}

// do sends one admin request. out may be nil. It returns the response's
// Location header, which Keycloak uses to name a created object.
func (a *admin) do(method, rel string, in, out any) (string, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return "", fmt.Errorf("encode: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, adminBase+rel, body)
	if err != nil {
		return "", fmt.Errorf("build %s %s: %w", method, rel, err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", method, rel, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s %s: HTTP %d", method, rel, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return "", fmt.Errorf("decode %s: %w", rel, err)
		}
	}
	return resp.Header.Get("Location"), nil
}

// labClient returns lab-spa's full representation, as a map so a PUT sends
// back every field Keycloak gave, changed or not.
func (a *admin) labClient() (map[string]any, error) {
	var list []map[string]any
	if _, err := a.do(http.MethodGet, "/clients?clientId="+clientID, nil, &list); err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("found %d clients named %s", len(list), clientID)
	}
	return list[0], nil
}

// withClient applies change to lab-spa, runs fn, and restores the client
// exactly as it was, whatever fn did.
func (a *admin) withClient(change func(map[string]any), fn func() error) error {
	orig, err := a.labClient()
	if err != nil {
		return err
	}
	id, _ := orig["id"].(string)
	changed := map[string]any{}
	for k, v := range orig {
		changed[k] = v
	}
	change(changed)
	if _, err := a.do(http.MethodPut, "/clients/"+id, changed, nil); err != nil {
		return err
	}
	runErr := fn()
	if _, err := a.do(http.MethodPut, "/clients/"+id, orig, nil); err != nil {
		return fmt.Errorf("restore %s: %w (run make lab-down && make lab-up)", clientID, err)
	}
	return runErr
}

// withRotatedKey adds a new RSA signing key that outranks the realm's
// current one, runs fn, and removes the key again.
func (a *admin) withRotatedKey(fn func() error) error {
	var realm struct {
		ID string `json:"id"`
	}
	if _, err := a.do(http.MethodGet, "", nil, &realm); err != nil {
		return err
	}
	loc, err := a.do(http.MethodPost, "/components", map[string]any{
		"name":         "oidcrun-rotated",
		"providerId":   "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider",
		"parentId":     realm.ID,
		"config": map[string][]string{
			"priority":  {"1000"},
			"keySize":   {"2048"},
			"algorithm": {"RS256"},
			"active":    {"true"},
			"enabled":   {"true"},
		},
	}, nil)
	if err != nil {
		return err
	}
	runErr := fn()
	if _, err := a.do(http.MethodDelete, "/components/"+path.Base(loc), nil, nil); err != nil {
		return fmt.Errorf("remove rotated key: %w (run make lab-down && make lab-up)", err)
	}
	return runErr
}
