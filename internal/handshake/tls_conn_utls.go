package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"

	"github.com/apernet/quic-go/quicvarint"
)

// utlsQUICConn adapts uTLS's UQUICConn to the tlsQUICConn interface, translating
// its QUIC event and connection-state types back into the crypto/tls
// equivalents. Native session states remain opaque and are never converted.
type utlsQUICConn struct {
	conn              utlsQUICClientConn
	resumptionEnabled bool
	// spec is retained because the transport parameters have to be written into
	// the ClientHello extension rather than handed to uTLS directly; see
	// SetTransportParameters.
	spec *utls.ClientHelloSpec
}

// Keep the native event source separate so error and shutdown paths can be
// tested without fabricating opaque TLS session state or corrupting a TLS peer.
type utlsQUICClientConn interface {
	Start(context.Context) error
	Close() error
	HandleData(utls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
	NextEvent() utls.QUICEvent
	StoreSession(*utls.SessionState) error
	ConnectionState() utls.ConnectionState
}

var _ tlsQUICConn = (*utlsQUICConn)(nil)

// newUTLSQUICClient creates a QUIC-TLS client emitting the parroted ClientHello.
//
// A caller-owned uTLS cache opts into resumption. The two TLS stacks have
// incompatible session state, so native events are consumed inside the adapter.
// 0-RTT remains disabled, including when a server issues an early-data ticket.
func newUTLSQUICClient(tlsConf *tls.Config, cache utls.ClientSessionCache) (*utlsQUICConn, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: nil TLS config with ChromeParrot")
	}
	uConf, err := utlsConfigFromStd(tlsConf)
	if err != nil {
		return nil, err
	}
	resume := cache != nil && !tlsConf.SessionTicketsDisabled
	if resume {
		if len(tlsConf.EncryptedClientHelloConfigList) > 0 {
			return nil, errors.New("quic: ChromeParrot session resumption with a custom ECH ClientHello is not supported")
		}
		uConf.SessionTicketsDisabled = false
		uConf.ClientSessionCache = cache
		uConf.OmitEmptyPsk = true
		// uTLS appends the real PSK extension after all shuffled extensions.
		// Its empty-cache encoding is omitted, preserving the cold profile.
		uConf.AlwaysIncludePSK = true
	}
	spec := chromeQUICClientHelloSpec(tlsConf.NextProtos)

	conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf, EnableSessionEvents: resume}, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("applying Chrome ClientHello spec: %w", err)
	}
	return &utlsQUICConn{conn: conn, spec: spec, resumptionEnabled: resume}, nil
}

// utlsConfigFromStd converts a crypto/tls client config into the uTLS
// equivalent.
//
// uTLS ships no converter, so this copies field by field. Any field that cannot
// be carried across is a hard error rather than a silent omission: dropping
// something like VerifyConnection would quietly weaken certificate validation.
func utlsConfigFromStd(c *tls.Config) (*utls.Config, error) {
	if c == nil {
		return &utls.Config{MinVersion: utls.VersionTLS13}, nil
	}
	if c.VerifyConnection != nil {
		// Takes a crypto/tls ConnectionState, which uTLS will never produce.
		return nil, errors.New("quic: tls.Config.VerifyConnection is not supported with ChromeParrot")
	}
	if c.GetConfigForClient != nil || len(c.Certificates) > 0 || c.GetCertificate != nil {
		return nil, errors.New("quic: server-side tls.Config fields are not supported with ChromeParrot")
	}

	uc := &utls.Config{
		Rand:                  c.Rand, //nolint:staticcheck // Preserve the caller's explicit legacy entropy policy in this compatibility adapter.
		Time:                  c.Time,
		RootCAs:               c.RootCAs,
		NextProtos:            c.NextProtos,
		ServerName:            c.ServerName,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		KeyLogWriter:          c.KeyLogWriter,
		// TLS 1.3 only, which QUIC requires regardless.
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
		// Explicit native-cache opt-in is applied by newUTLSQUICClient.
		SessionTicketsDisabled: true,
	}

	if c.GetClientCertificate != nil {
		get := c.GetClientCertificate
		uc.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			cert, err := get(&tls.CertificateRequestInfo{
				AcceptableCAs:    cri.AcceptableCAs,
				SignatureSchemes: signatureSchemesToStd(cri.SignatureSchemes),
				Version:          cri.Version,
			})
			if err != nil {
				return nil, err
			}
			if cert == nil {
				return &utls.Certificate{}, nil
			}
			return &utls.Certificate{
				Certificate:                 cert.Certificate,
				PrivateKey:                  cert.PrivateKey,
				OCSPStaple:                  cert.OCSPStaple,
				SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
				Leaf:                        cert.Leaf,
			}, nil
		}
	}

	// GREASE ECH is covered by the ClientHello spec; a caller-supplied config list
	// takes precedence.
	if len(c.EncryptedClientHelloConfigList) > 0 {
		uc.EncryptedClientHelloConfigList = c.EncryptedClientHelloConfigList
	}
	return uc, nil
}

func signatureSchemesToStd(in []utls.SignatureScheme) []tls.SignatureScheme {
	out := make([]tls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = tls.SignatureScheme(s)
	}
	return out
}

func (c *utlsQUICConn) Start(ctx context.Context) error { return stdUTLSError(c.conn.Start(ctx)) }
func (c *utlsQUICConn) Close() error                    { return stdUTLSError(c.conn.Close()) }

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return stdUTLSError(c.conn.HandleData(utlsEncryptionLevel(level), data))
}

// SetTransportParameters installs quic-go's marshalled transport parameters into
// the ClientHello.
//
// uTLS's own SetTransportParameters does not reach the ClientHello when a preset
// is in use, so the bytes must be written into the spec's
// quic_transport_parameters extension. uTLS models that extension as (id, value)
// pairs and marshals it itself, so the blob is split back into pairs here.
// Splitting rather than re-deriving preserves our per-connection ordering.
func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	// Still call through so uTLS's internal copy stays consistent.
	c.conn.SetTransportParameters(params)

	tps, err := splitTransportParameters(params)
	if err != nil {
		// Our own marshaller produced these, so this is unreachable short of a bug.
		panic(fmt.Sprintf("handshake BUG: cannot split marshalled transport parameters: %s", err))
	}
	for _, ext := range c.spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.TransportParameters = tps
			return
		}
	}
	panic("handshake BUG: Chrome ClientHello spec has no quic_transport_parameters extension")
}

// splitTransportParameters parses a marshalled transport parameter blob back into
// individual (id, value) pairs, preserving order.
func splitTransportParameters(b []byte) (utls.TransportParameters, error) {
	var tps utls.TransportParameters
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if uint64(len(b)) < l {
			return nil, fmt.Errorf("transport parameter 0x%x truncated: want %d bytes, have %d", id, l, len(b))
		}
		val := make([]byte, l)
		copy(val, b[:l])
		b = b[l:]
		tps = append(tps, &utls.FakeQUICTransportParameter{Id: id, Val: val})
	}
	return tps, nil
}

func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	for {
		ev := c.conn.NextEvent()
		if (ev.Kind == utls.QUICSetReadSecret || ev.Kind == utls.QUICSetWriteSecret || ev.Kind == utls.QUICWriteData) && ev.Level == utls.QUICEncryptionLevelEarly {
			return tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: errors.New("quic: unexpected 0-RTT event with ChromeParrot")}
		}
		out := tls.QUICEvent{
			Level: stdEncryptionLevel(ev.Level),
			Data:  ev.Data,
			Suite: ev.Suite,
		}
		switch ev.Kind {
		case utls.QUICResumeSession, utls.QUICStoreSession:
			if !c.resumptionEnabled || ev.SessionState == nil {
				return tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: errors.New("quic: unexpected or empty ChromeParrot session event")}
			}
			// ResumeSession pauses TLS until the next NextEvent. Clear this before
			// advancing so early secrets and early_data can never be produced.
			ev.SessionState.EarlyData = false
			if ev.Kind == utls.QUICStoreSession {
				if err := c.conn.StoreSession(ev.SessionState); err != nil {
					return tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: stdUTLSError(err)}
				}
			}
			continue
		case utls.QUICErrorEvent:
			err := ev.Err
			if err == nil {
				err = errors.New("quic: empty ChromeParrot TLS error event")
			}
			return tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: stdUTLSError(err)}
		case utls.QUICNoEvent:
			out.Kind = tls.QUICNoEvent
		case utls.QUICSetReadSecret:
			out.Kind = tls.QUICSetReadSecret
		case utls.QUICSetWriteSecret:
			out.Kind = tls.QUICSetWriteSecret
		case utls.QUICWriteData:
			out.Kind = tls.QUICWriteData
		case utls.QUICTransportParameters:
			out.Kind = tls.QUICTransportParameters
		case utls.QUICTransportParametersRequired:
			out.Kind = tls.QUICTransportParametersRequired
		case utls.QUICRejectedEarlyData:
			out.Kind = tls.QUICRejectedEarlyData
		case utls.QUICHandshakeDone:
			out.Kind = tls.QUICHandshakeDone
		default:
			return tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: fmt.Errorf("quic: unexpected uTLS QUIC event kind %d", ev.Kind)}
		}
		return out
	}
}

// Preserve the original error chain while making its alert visible to the
// crypto/tls-based QUIC error classifier. The alert types have distinct Go
// identities even though they carry the same TLS alert number.
type utlsAlertError struct {
	err   error
	alert tls.AlertError
}

func (e *utlsAlertError) Error() string   { return e.err.Error() }
func (e *utlsAlertError) Unwrap() []error { return []error{e.err, e.alert} }

func stdUTLSError(err error) error {
	if alert, ok := errors.AsType[utls.AlertError](err); ok {
		return &utlsAlertError{err: err, alert: tls.AlertError(alert)}
	}
	return err
}

func (c *utlsQUICConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("quic: SendSessionTicket is server-only and unsupported with ChromeParrot")
}

func (c *utlsQUICConn) StoreSession(*tls.SessionState) error {
	return errors.New("quic: crypto/tls session state cannot be stored with ChromeParrot; native session events are handled internally")
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	s := c.conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  true, //nolint:staticcheck // Preserve the always-true crypto/tls compatibility field for existing callers.
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		ECHAccepted:                 s.ECHAccepted,
	}
}

func utlsEncryptionLevel(l tls.QUICEncryptionLevel) utls.QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return utls.QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelEarly:
		return utls.QUICEncryptionLevelEarly
	case tls.QUICEncryptionLevelHandshake:
		return utls.QUICEncryptionLevelHandshake
	case tls.QUICEncryptionLevelApplication:
		return utls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown encryption level %d", l))
	}
}

func stdEncryptionLevel(l utls.QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case utls.QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case utls.QUICEncryptionLevelEarly:
		return tls.QUICEncryptionLevelEarly
	case utls.QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	case utls.QUICEncryptionLevelApplication:
		return tls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown uTLS encryption level %d", l))
	}
}
