// Package render produces subscription-format output from parsed proxies or
// raw URI strings.
package render

import (
	"encoding/base64"
	"strings"
)

// V2Ray emits the legacy V2RayN-style subscription: base64(join(uris, "\n")).
//
// Takes raw URI strings (not parsed Proxy structs) so that URIs which fail to
// parse can still appear in the output — V2Ray-style subscriptions are
// pass-through by convention. Callers should fetch and filter URIs first.
func V2Ray(uris []string) []byte {
	body := strings.Join(uris, "\n")
	return []byte(base64.StdEncoding.EncodeToString([]byte(body)))
}
