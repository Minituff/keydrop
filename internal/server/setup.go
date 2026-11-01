package server

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"text/template"
)

// The agent setup guide is one template (web/agent-setup.md.tmpl) with two
// renderings: a server's own copy, served at /setup.md and shown on the
// "Set up an agent" page with its address and pins filled in, and the
// generic copy checked into docs/agents.md (TestAgentsDoc keeps it in
// step). Everything in it is public: no token, no setup code.

var setupTmpl = template.Must(template.New("agent-setup.md.tmpl").Funcs(template.FuncMap{
	"next": func() int { return 0 }, // replaced per render
}).Option("missingkey=error").ParseFS(webFS, "web/agent-setup.md.tmpl"))

// setupGuide is what the template needs.
type setupGuide struct {
	// Generic is the docs copy: placeholders for the values, and the steps
	// to install a server first.
	Generic bool
	// URL is the address agents use; CertPin (sha256:<hex>, checked by the
	// CLI) and KeyPin (sha256//<base64>, checked by curl) are empty when
	// the certificate is one the system already trusts.
	URL, CertPin, KeyPin string
	// CLI is whether the server hands out CLI builds (install.sh works).
	CLI bool
}

// genericGuide is the docs copy's placeholders.
var genericGuide = setupGuide{Generic: true, URL: "<server-url>", CertPin: "<cert-pin>", KeyPin: "<key-pin>", CLI: true}

func (g setupGuide) render() (string, error) {
	n := 0
	t, err := setupTmpl.Clone()
	if err != nil {
		return "", err
	}
	t.Funcs(template.FuncMap{"next": func() int { n++; return n }})
	h := "#"
	if g.Generic {
		h = "##" // it sits under the docs page's own title
	}
	var b bytes.Buffer
	err = t.Execute(&b, struct {
		setupGuide
		H string
	}{g, h})
	return b.String(), err
}

// handleSetupGuide serves the guide for this server, filled in with the
// address the agent reached it on. It follows install.sh's transport
// rules: over https straight to keydrop (with its pins), or through a
// trusted proxy whose public URL is https; never over plain http, where
// the pins in it could have been swapped.
func (s *Server) handleSetupGuide(w http.ResponseWriter, r *http.Request) {
	base, keyPin, certPin, errMsg := s.installTarget(r, "setup.md")
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	out, err := setupGuide{URL: base, CertPin: certPin, KeyPin: keyPin, CLI: len(s.cfg.CLI) > 0}.render()
	if err != nil {
		http.Error(w, "couldn't render the setup guide", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Write([]byte(out))
}

// fetchCommands are curl commands for a public path, the same two ways as
// the install commands: public through a proxy with a real certificate,
// direct to keydrop with its key pinned.
func (c Config) fetchCommands(path string) (public, direct string) {
	if c.KeyPin == "" || len(c.TrustedProxies) > 0 {
		if strings.HasPrefix(c.PublicURL, "https://") && !c.PublicURLGuess {
			public = "curl -fsS " + strings.TrimRight(c.PublicURL, "/") + path
		}
	}
	if c.KeyPin != "" && c.DirectURL != "" {
		direct = "curl -fsSk --pinnedpubkey '" + c.KeyPin + "' " + strings.TrimRight(c.DirectURL, "/") + path
	}
	return public, direct
}

// SetupCommands are the short versions of the setup prompt: one sentence
// to paste into an agent, which fetches this server's /setup.md.
func (c Config) SetupCommands() (public, direct string) {
	public, direct = c.fetchCommands("/setup.md")
	wrap := func(cmd string) string {
		if cmd == "" {
			return ""
		}
		return "Run `" + cmd + "` and follow it to set up keydrop."
	}
	return wrap(public), wrap(direct)
}

// pageGuide is the guide as /setup.md would serve it to an agent using the
// page's preferred command: direct and pinned when there's a pin, else
// through the public https URL.
func (c Config) pageGuide() (setupGuide, bool) {
	if c.KeyPin != "" && c.DirectURL != "" {
		return setupGuide{URL: strings.TrimRight(c.DirectURL, "/"), CertPin: c.CertPin, KeyPin: c.KeyPin, CLI: len(c.CLI) > 0}, true
	}
	if strings.HasPrefix(c.PublicURL, "https://") && !c.PublicURLGuess {
		return setupGuide{URL: strings.TrimRight(c.PublicURL, "/"), CLI: len(c.CLI) > 0}, true
	}
	return setupGuide{}, false
}

func (s *Server) handleAgentSetup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	data := page{"Title": "Set up an agent", "CertPin": s.cfg.CertPin, "KeyPin": s.cfg.KeyPin}
	if g, ok := s.cfg.pageGuide(); ok {
		prompt, err := g.render()
		if err != nil {
			http.Error(w, "couldn't render the setup guide", http.StatusInternalServerError)
			return
		}
		public, direct := s.cfg.SetupCommands()
		data["Prompt"], data["Public"], data["Direct"], data["URL"] = prompt, public, direct, g.URL
	}
	s.render(w, r, "agent_setup", http.StatusOK, se, data)
}
