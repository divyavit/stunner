package stunner

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/l7mp/stunner/internal/util"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

// URI is the specification of a STUNner listener URI
type URI struct {
	Protocol, Address, Username, Password string
	Port                                  int
	Addr                                  net.Addr
}

// ParseURI parses a STUN/TURN server URI into its components. It accepts both the hierarchical form
// ("turn://user:pass@host:port?transport=udp") and the RFC 7065 form ("turn:host:port?transport=udp",
// note the single colon). IPv6 hosts must be bracketed, e.g. "turn://[2001:db8::1]:3478". The special
// values "-" and "file://-" denote standard input.
func ParseURI(uri string) (*URI, error) {
	s := URI{}

	// handle stdin/out
	if uri == "-" || uri == "file://-" {
		s.Protocol = "file"
		// make turncat conf happy
		s.Port = 1
		s.Addr = &util.FileConnAddr{File: os.Stdin}
		return &s, nil
	}

	// RFC 7065 TURN URIs use an opaque form ("turn:host:port?...") that net/url does not split into
	// host and port. Upgrade recognized schemes to the hierarchical "scheme://host:port?..." form so
	// url.Parse populates Host/User and handles bracketed IPv6 hosts correctly.
	u, err := url.Parse(upgradeTurnURI(uri))
	if err != nil {
		return nil, fmt.Errorf("invalid URI %q: %w", uri, err)
	}

	if hasUnbracketedIPv6(u) {
		return nil, fmt.Errorf("invalid URI %q: IPv6 host must be bracketed, e.g. [%s]", uri, u.Hostname())
	}

	proto, err := getStunnerProtoForURI(u)
	if err != nil {
		return nil, err
	}
	s.Protocol = proto
	s.Address = u.Hostname()
	s.Username = u.User.Username()
	if password, found := u.User.Password(); found {
		s.Password = password
	}

	// the default port depends on whether the protocol is (D)TLS
	s.Port = 3478
	if p := strings.ToLower(proto); p == "turn-tls" || p == "turn-dtls" {
		s.Port = 443
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port in URI %q: %w", uri, err)
		}
		s.Port = port
	}

	// resolve into a net.Addr of the family implied by the address; net.JoinHostPort brackets IPv6
	hostport := net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
	switch strings.ToLower(proto) {
	case "udp", "udp4", "dtls", "turn-udp", "turn-dtls":
		s.Addr, err = net.ResolveUDPAddr("udp", hostport)
	case "tcp", "tcp4", "tls", "turn-tcp", "turn-tls":
		s.Addr, err = net.ResolveTCPAddr("tcp", hostport)
	case "ip", "ip4":
		s.Addr, err = net.ResolveIPAddr("ip", s.Address)
	case "unix", "unixgram", "unixpacket":
		s.Addr, err = net.ResolveUnixAddr("unix", s.Address)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", proto)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid address in URI %q: %w", uri, err)
	}

	return &s, nil
}

// String returns the URI in the hierarchical "turn://host:port?transport=udp" URL form. It is the
// inverse of ParseURI; the RFC 7065 form is equally accepted on the way back in.
func (u *URI) String() string {
	return u.format("://")
}

// AsRFC7065String returns the URI in the RFC 7065 "turn:host:port?transport=udp" form (the scheme is
// followed by a single colon, no "//"). This is the syntax WebRTC ICE server configurations expect.
func (u *URI) AsRFC7065String() string {
	return u.format(":")
}

// format renders the URI as a STUN/TURN server URI, using sep as the scheme separator (":" for the
// RFC 7065 TURN URI form, "://" for a standard, net/url-parseable URL). It returns "" if the protocol
// is not a known TURN listener protocol.
func (u *URI) format(sep string) string {
	proto, err := stnrv1.NewListenerProtocol(u.Protocol)
	if err != nil {
		return ""
	}
	var service, transport string
	switch proto {
	case stnrv1.ListenerProtocolTURNUDP:
		service, transport = "turn", "udp"
	case stnrv1.ListenerProtocolTURNTCP:
		service, transport = "turn", "tcp"
	case stnrv1.ListenerProtocolTURNDTLS:
		service, transport = "turns", "udp"
	case stnrv1.ListenerProtocolTURNTLS:
		service, transport = "turns", "tcp"
	default:
		return ""
	}
	return fmt.Sprintf("%s%s%s?transport=%s", service, sep,
		net.JoinHostPort(u.Address, strconv.Itoa(u.Port)), transport)
}

// NewURIFromListener builds a server URI from a listener configuration. The public address and port
// are preferred over the listen address and port; a missing or placeholder address falls back to
// "0.0.0.0". The returned URI carries no resolved net.Addr — it is meant for its string forms.
func NewURIFromListener(l *stnrv1.ListenerConfig) (*URI, error) {
	proto, err := stnrv1.NewListenerProtocol(l.Protocol)
	if err != nil {
		return nil, err
	}

	addr := l.PublicAddr
	if addr == "" {
		addr = l.Addr
	}
	if addr == "" || addr == stnrv1.DefaultNodeAddressPlaceholder {
		addr = "0.0.0.0"
	}

	port := l.PublicPort
	if port == 0 {
		port = l.Port
	}

	return &URI{Protocol: proto.String(), Address: addr, Port: port}, nil
}

// upgradeTurnURI rewrites an RFC 7065 TURN URI ("turn:host..." / "turns:host...") to the hierarchical
// "turn://host..." form that net/url parses into host/user/port. URIs that already use "//", or that
// carry no recognized TURN scheme, are returned unchanged.
func upgradeTurnURI(uri string) string {
	lower := strings.ToLower(uri)
	for _, scheme := range []string{"turn", "turns"} {
		prefix := scheme + ":"
		if strings.HasPrefix(lower, prefix) && !strings.HasPrefix(lower, prefix+"//") {
			return uri[:len(prefix)] + "//" + uri[len(prefix):]
		}
	}
	return uri
}

// hasUnbracketedIPv6 reports whether a parsed URL's authority carries an unbracketed IPv6 literal,
// which RFC 3986 forbids.
func hasUnbracketedIPv6(u *url.URL) bool {
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.To4() == nil && u.Port() != "" &&
		u.Host != net.JoinHostPort(u.Hostname(), u.Port())
}

// getStunnerProtoForURI derives the canonical protocol name from a parsed URI. TURN URIs
// ("turn"/"turns" scheme) map to a TURN listener protocol via their "?transport=" query per RFC 7065;
// any other scheme is taken as a plain transport/socket protocol (udp, tcp, unix, ip, ...) and parsed
// directly. An empty scheme defaults to "turn".
func getStunnerProtoForURI(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "turn"
	}

	if scheme != "turn" && scheme != "turns" {
		// plain transport/socket scheme, e.g. "udp://", "tcp://", "unix://"
		p, err := stnrv1.NewProtocol(scheme)
		if err != nil {
			return "", fmt.Errorf("invalid scheme/protocol in URI %q", u.String())
		}
		return p.String(), nil
	}

	transport := "udp"
	if q := u.Query()["transport"]; len(q) > 0 {
		transport = strings.ToLower(q[0])
	}

	switch {
	// fully specified transport names (the "turn"/"turns" scheme is irrelevant here)
	case transport == "tls":
		return stnrv1.ProtocolTURNTLS.String(), nil
	case transport == "dtls":
		return stnrv1.ProtocolTURNDTLS.String(), nil
	// RFC 7065 (scheme, transport) combinations
	case scheme == "turn" && transport == "udp":
		return stnrv1.ProtocolTURNUDP.String(), nil
	case scheme == "turn" && transport == "tcp":
		return stnrv1.ProtocolTURNTCP.String(), nil
	case scheme == "turns" && transport == "udp":
		return stnrv1.ProtocolTURNDTLS.String(), nil
	case scheme == "turns" && transport == "tcp":
		return stnrv1.ProtocolTURNTLS.String(), nil
	default:
		return "", fmt.Errorf("invalid scheme/protocol in URI %q", u.String())
	}
}
