// Package fetch handles parallel retrieval of upstream subscription URLs and
// filtering of returned lines by allowed schemes.
package fetch

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Client wraps an http.Client with the upstream URL templates and scheme filter
// applied during aggregation. One Client is shared across all requests.
type Client struct {
	HTTP          *http.Client
	Upstreams     []string // URL templates with %s for subId
	ValidPrefixes []string // e.g. "vless://", "vmess://"
}

// Aggregate fetches all upstreams in parallel and returns filtered URI lines
// in upstream order. Failed upstreams contribute zero lines but do not abort
// the aggregation — partial success is still returned.
func (c *Client) Aggregate(subID string) []string {
	results := make([][]string, len(c.Upstreams))
	var wg sync.WaitGroup
	for i, tmpl := range c.Upstreams {
		wg.Add(1)
		go func(i int, tmpl string) {
			defer wg.Done()
			results[i] = c.fetchOne(fmt.Sprintf(tmpl, subID))
		}(i, tmpl)
	}
	wg.Wait()

	var lines []string
	for _, chunk := range results {
		lines = append(lines, chunk...)
	}
	return lines
}

// fetchOne retrieves a single upstream URL, decodes base64 if applicable, and
// returns lines matching ValidPrefixes. Returns nil on any error.
func (c *Client) fetchOne(url string) []string {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("build request: %v", err)
		return nil
	}
	req.Header.Set("User-Agent", "microsubsproxy/1.0")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		log.Printf("upstream fail: %v", err)
		return nil
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("upstream read fail: %v", err)
		return nil
	}
	text := strings.TrimSpace(string(raw))

	// 3x-ui may return base64 or plain; try base64 first.
	if dec, err := base64.StdEncoding.DecodeString(text); err == nil {
		text = string(dec)
	}

	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		for _, p := range c.ValidPrefixes {
			if strings.HasPrefix(ln, p) {
				lines = append(lines, ln)
				break
			}
		}
	}
	return lines
}
