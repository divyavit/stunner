package client

import (
	"encoding/json"
	"net/url"
	"strings"

	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

func decodeConfig(r []byte) ([]*stnrv1.StunnerConfig, error) {
	c := stnrv1.StunnerConfig{}
	if err := json.Unmarshal(r, &c); err != nil {
		return nil, err
	}

	// copy

	return []*stnrv1.StunnerConfig{&c}, nil
}

func decodeConfigList(r []byte) ([]*stnrv1.StunnerConfig, error) {
	l := ConfigList{}
	if err := json.Unmarshal(r, &l); err != nil {
		return nil, err
	}
	return l.Items, nil
}

// getURI parses a config origin into a URL. The origin is one of: (1) a bare network address
// "host:port", optionally followed by a "/path", which defaults to the http scheme, (2) a full URL
// carrying an explicit scheme (http, https, ws, wss or file), or (3) a file path. IPv6 hosts must be
// given in RFC 3986 bracketed form, e.g. "[::1]:port" or "http://[::1]:port"; url.Parse rejects an
// unbracketed IPv6 host.
func getURI(addr string) (*url.URL, error) {
	if !strings.Contains(addr, "://") {
		// no scheme: treat addr as a bare network address and default to http
		addr = "http://" + addr
	}
	return url.Parse(addr)
}

// wsURI converts a config origin into a websocket URL for the given API
// endpoint. The scheme is mapped to its websocket equivalent: https and wss
// become wss, everything else becomes ws.
func wsURI(addr, endpoint, node string) (string, error) {
	uri, err := getURI(addr)
	if err != nil {
		return "", err
	}

	switch uri.Scheme {
	case "https", "wss":
		uri.Scheme = "wss"
	default:
		uri.Scheme = "ws"
	}
	uri.Path = endpoint
	v := url.Values{}
	v.Set("watch", "true")
	if node != "" {
		v.Set("node", node)
	}
	uri.RawQuery = v.Encode()

	return uri.String(), nil
}
