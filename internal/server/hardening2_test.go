package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/store"
)

// A refused call on a canary still counts, and the answer is the same as on
// an ordinary secret.
func TestRefusedCallsTouchCanary(t *testing.T) {
	h := newHarness(t)
	h.setup()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(h.st.PutValue("lab", "DECOY", []byte("fake-decoy-value"), nil))
	must(h.st.PutValue("lab", "REAL", []byte("fake-real-value"), nil))
	must(h.st.SetCanary("lab", "DECOY", true))
	adder, _ := h.st.CreateToken("adder", []string{"lab"}, store.PermAdd, nil)
	writer, _ := h.st.CreateToken("writer", []string{"lab"}, store.PermWrite, nil)
	reader, _ := h.st.CreateToken("reader", []string{"lab"}, store.PermRead, nil)

	hits := func() int {
		n := 0
		list, _ := h.st.CanaryHits()
		for _, c := range list {
			n += c.Count
		}
		return n
	}
	for _, c := range []struct {
		name, tok, method, path string
		body                    any
	}{
		{"add token's overwrite", adder, "PUT", "", map[string]any{"value": "x", "overwrite": true}},
		{"write without overwrite", writer, "PUT", "", map[string]any{"value": "x"}},
		{"read token's write", reader, "PUT", "", map[string]any{"value": "x"}},
		{"bad status", writer, "POST", "/status", map[string]any{"status": "nonsense"}},
		{"ack", writer, "POST", "/ack", nil},
	} {
		before := hits()
		dc, _, draw := h.api(c.method, "/api/v1/secrets/lab/DECOY"+c.path, c.tok, c.body)
		if hits() != before+1 {
			t.Fatalf("%s: not a touch", c.name)
		}
		rc, _, rraw := h.api(c.method, "/api/v1/secrets/lab/REAL"+c.path, c.tok, c.body)
		if hits() != before+1 {
			t.Fatalf("%s: touched on an ordinary secret", c.name)
		}
		same := strings.ReplaceAll(string(draw), "DECOY", "REAL")
		if dc != rc || same != string(rraw) {
			t.Fatalf("%s: a canary answers differently: %d %s / %d %s", c.name, dc, draw, rc, rraw)
		}
	}
}

func TestReadPurposeIsCleaned(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "K", []byte("fake-purpose-value"), nil)
	tok := h.createToken("bot", "lab")
	h.api("POST", "/api/v1/secrets/lab/K/reveal?purpose=deploy%E2%80%AE%1B%5B31m%F3%A0%84%80", tok, nil)
	ev := h.srv.audit.Recent(1)[0]
	if ev.Action != "secret.read" || ev.Detail != "agent says: deploy[31m" {
		t.Fatalf("%+v", ev)
	}
}

func TestPairPollIsLimited(t *testing.T) {
	h := newHarness(t)
	var code int
	for i := 0; i <= pollsPerMinute; i++ {
		code, _ = h.apiFrom("10.0.0.5", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": "nope"})
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("poll %d", code)
	}
	if code, _ := h.apiFrom("10.0.0.6", "POST", "/api/v1/pair/poll", "", "", map[string]string{"poll": "nope"}); code == http.StatusTooManyRequests {
		t.Fatal("the limit is per address")
	}
}

func TestInstallScriptDoesntNameTheVersion(t *testing.T) {
	var b strings.Builder
	if err := installScript.Execute(&b, map[string]string{"Base": "https://x.test", "KeyPin": "sha256//AA"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "keydrop v") || strings.Contains(b.String(), "<no value>") {
		t.Fatal(b.String())
	}
}

func TestTokenPageWarnsBeforeRotating(t *testing.T) {
	h := newHarness(t)
	h.setup()
	_, tok := h.tokenWithLifetime("bot", "lab", "30")
	h.apiFrom("10.0.0.5", "GET", "/api/v1/whoami", tok, "", nil)
	if _, page := h.get("/token/bot"); strings.Contains(page, "Also used recently") {
		t.Fatal("warned with one address")
	}
	h.apiFrom("10.0.0.66", "GET", "/api/v1/whoami", tok, "", nil)
	if _, page := h.get("/token/bot"); !strings.Contains(page, "Also used recently from 10.0.0.5") {
		t.Fatal("no warning with two addresses")
	}
}
