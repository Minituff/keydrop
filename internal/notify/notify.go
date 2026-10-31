// Package notify sends optional webhooks when secrets are added or requested.
// Payloads carry names and descriptions only, never values.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Event is what a webhook is told about.
type Event struct {
	Event       string `json:"event"` // secret.set, secret.requested
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	By          string `json:"by"`
	URL         string `json:"url,omitempty"`
}

// Notifier posts events to URL. Format is "json" (the Event as-is),
// "discord" ({"content": ...}) or "ntfy" (plain-text body).
type Notifier struct {
	URL    string
	Format string
	Client *http.Client
}

func (n *Notifier) text(e Event) string {
	var s string
	switch e.Event {
	case "secret.requested":
		s = fmt.Sprintf("🔑 %s is asking for secret `%s/%s`", e.By, e.Namespace, e.Name)
	default:
		s = fmt.Sprintf("🔑 Secret `%s/%s` was set by %s", e.Namespace, e.Name, e.By)
	}
	if e.Description != "" {
		s += "\n> " + e.Description
	}
	if e.URL != "" {
		s += "\n" + e.URL
	}
	return s
}

// Send posts e in the background. Failures are logged, not returned: a
// webhook outage must not block storing a secret.
func (n *Notifier) Send(e Event) {
	if n == nil || n.URL == "" {
		return
	}
	go func() {
		var body []byte
		ctype := "application/json"
		switch n.Format {
		case "discord":
			body, _ = json.Marshal(map[string]string{"content": n.text(e)})
		case "ntfy":
			body, ctype = []byte(n.text(e)), "text/plain; charset=utf-8"
		default:
			body, _ = json.Marshal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
		if err != nil {
			log.Printf("webhook: %v", err)
			return
		}
		req.Header.Set("Content-Type", ctype)
		c := n.Client
		if c == nil {
			c = http.DefaultClient
		}
		resp, err := c.Do(req)
		if err != nil {
			log.Printf("webhook: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("webhook: %s returned %s", e.Event, resp.Status)
		}
	}()
}
