package handshake

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

type chromeSessionCache struct {
	utls.ClientSessionCache
	puts        atomic.Int32
	hits        atomic.Int32
	earlyStores atomic.Int32
}

func newChromeSessionCache() *chromeSessionCache {
	return &chromeSessionCache{ClientSessionCache: utls.NewLRUClientSessionCache(4)}
}

func (c *chromeSessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	state, ok := c.ClientSessionCache.Get(key)
	if ok {
		c.hits.Add(1)
	}
	return state, ok
}

func (c *chromeSessionCache) Put(key string, state *utls.ClientSessionState) {
	if state != nil {
		c.puts.Add(1)
		_, session, err := state.ResumptionState()
		if err != nil || session == nil || session.EarlyData {
			c.earlyStores.Add(1)
		}
	}
	c.ClientSessionCache.Put(key, state)
}

type chromeHello struct {
	ids        []uint16
	extensions map[uint16][]byte
}

// Parse actual handshake bytes emitted through QUIC CRYPTO, not the input
// preset: a warm PSK binder and HRR ClientHello are produced only at runtime.
func parseChromeHellos(t *testing.T, data []byte) []chromeHello {
	t.Helper()
	var hellos []chromeHello
	for len(data) > 0 {
		require.GreaterOrEqual(t, len(data), 4)
		require.Equal(t, byte(1), data[0])
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		require.GreaterOrEqual(t, len(data), 4+n)
		body := data[4 : 4+n]
		data = data[4+n:]
		require.GreaterOrEqual(t, len(body), 35)
		body = body[34:]
		sidLen := int(body[0])
		require.GreaterOrEqual(t, len(body), 1+sidLen+2)
		body = body[1+sidLen:]
		cipherLen := int(binary.BigEndian.Uint16(body))
		require.GreaterOrEqual(t, len(body), 2+cipherLen+1)
		body = body[2+cipherLen:]
		compressionLen := int(body[0])
		require.GreaterOrEqual(t, len(body), 1+compressionLen+2)
		body = body[1+compressionLen:]
		extLen := int(binary.BigEndian.Uint16(body))
		require.Equal(t, len(body)-2, extLen)
		body = body[2:]
		hello := chromeHello{extensions: make(map[uint16][]byte)}
		for len(body) > 0 {
			require.GreaterOrEqual(t, len(body), 4)
			id, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
			require.GreaterOrEqual(t, len(body), 4+n)
			_, duplicate := hello.extensions[id]
			require.False(t, duplicate, "duplicate extension %d", id)
			hello.ids = append(hello.ids, id)
			hello.extensions[id] = bytes.Clone(body[4 : 4+n])
			body = body[4+n:]
		}
		hellos = append(hellos, hello)
	}
	return hellos
}

var (
	chromeTestClientTP = []byte{0x0f, 0x00, 0x01, 0x01, 0x1e, 0x04, 0x02, 0x40, 0x40}
	chromeTestServerTP = []byte{0x00, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x20}
)

type chromeHandshakeResult struct {
	client, server             tls.ConnectionState
	hellos                     []chromeHello
	clientPeerTP, serverPeerTP []byte
	secrets                    int
}

func runChromeHandshake(t *testing.T, clientConf, serverConf *tls.Config, cache utls.ClientSessionCache) (result chromeHandshakeResult, resultErr error) {
	t.Helper()
	client, err := newUTLSQUICClient(clientConf, cache)
	if err != nil {
		return result, err
	}
	defer client.Close()
	server := tls.QUICServer(&tls.QUICConfig{TLSConfig: serverConf, EnableSessionEvents: true})
	defer server.Close()
	client.SetTransportParameters(chromeTestClientTP)
	server.SetTransportParameters(chromeTestServerTP)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		return result, err
	}
	if err := server.Start(ctx); err != nil {
		return result, err
	}
	var clientInitial []byte
	var clientDone, serverDone, ticketSent bool
	defer func() {
		result.client, result.server = client.ConnectionState(), server.ConnectionState()
		if len(clientInitial) > 0 {
			result.hellos = parseChromeHellos(t, clientInitial)
		}
	}()
	for range 100 {
		progress := false
		for side := range 2 {
			var source, destination tlsQUICConn = client, server
			if side == 1 {
				source, destination = server, client
			}
			for {
				ev := source.NextEvent()
				if ev.Kind == tls.QUICNoEvent {
					break
				}
				progress = true
				switch ev.Kind {
				case tls.QUICWriteData:
					require.NotEqual(t, tls.QUICEncryptionLevelEarly, ev.Level)
					if side == 0 && ev.Level == tls.QUICEncryptionLevelInitial {
						clientInitial = append(clientInitial, ev.Data...)
					}
					if err := destination.HandleData(ev.Level, ev.Data); err != nil {
						return result, err
					}
				case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
					require.NotEqual(t, tls.QUICEncryptionLevelEarly, ev.Level, "no early traffic secrets on either peer")
					result.secrets++
				case tls.QUICTransportParameters:
					if side == 0 {
						result.clientPeerTP = bytes.Clone(ev.Data)
					} else {
						result.serverPeerTP = bytes.Clone(ev.Data)
					}
				case tls.QUICHandshakeDone:
					if side == 0 {
						clientDone = true
					} else {
						serverDone = true
						// Intentionally issue a 0-RTT-capable ticket. The adapter must
						// suppress early data, rather than relying on the test server.
						if err := server.SendSessionTicket(tls.QUICSessionTicketOptions{EarlyData: true}); err != nil {
							return result, err
						}
						ticketSent = true
					}
				case tls.QUICResumeSession:
					require.Equal(t, 1, side, "native client session events must not escape the adapter")
				case tls.QUICErrorEvent:
					return result, ev.Err
				default:
					t.Fatalf("unexpected TLS event %v from peer %d", ev.Kind, side)
				}
			}
		}
		if !progress {
			if clientDone && serverDone && ticketSent {
				return result, nil
			}
			return result, errors.New("QUIC TLS handshake stalled before completion")
		}
	}
	return result, errors.New("QUIC TLS handshake exceeded bounded event rounds")
}

func assertChromeHandshake(t *testing.T, result chromeHandshakeResult, resume, hrr bool) {
	t.Helper()
	for _, state := range []tls.ConnectionState{result.client, result.server} {
		require.True(t, state.HandshakeComplete)
		require.Equal(t, tls.VersionTLS13, int(state.Version))
		require.Equal(t, "h3", state.NegotiatedProtocol)
		require.Equal(t, resume, state.DidResume)
	}
	require.NotEmpty(t, result.client.VerifiedChains)
	require.Equal(t, "localhost", result.client.ServerName)
	require.Equal(t, chromeTestClientTP, result.serverPeerTP)
	require.Equal(t, chromeTestServerTP, result.clientPeerTP)
	require.Positive(t, result.secrets)
	count := 1
	if hrr {
		count = 2
	}
	require.Len(t, result.hellos, count)
	for _, hello := range result.hellos {
		require.NotContains(t, hello.extensions, uint16(42), "early_data must not be serialized")
		require.Equal(t, chromeTestClientTP, hello.extensions[57], "transport parameters retain exact encoding and order")
		if resume {
			require.Equal(t, uint16(41), hello.ids[len(hello.ids)-1], "PSK is the final extension")
			psk := hello.extensions[41]
			require.Greater(t, len(psk), 2)
			identitiesLen := int(binary.BigEndian.Uint16(psk))
			require.Greater(t, len(psk), 2+identitiesLen+2)
			binders := psk[2+identitiesLen:]
			require.Equal(t, len(binders)-2, int(binary.BigEndian.Uint16(binders)))
			require.GreaterOrEqual(t, int(binders[2]), 32)
			require.Equal(t, len(binders)-3, int(binders[2]))
		} else {
			require.NotContains(t, hello.extensions, uint16(41))
		}
	}
	if hrr {
		share := result.hellos[1].extensions[51]
		require.GreaterOrEqual(t, len(share), 6)
		require.Equal(t, uint16(tls.CurveP256), binary.BigEndian.Uint16(share[2:]))
		if resume {
			require.NotEqual(t, result.hellos[0].extensions[41], result.hellos[1].extensions[41], "HRR recomputes the binder")
		}
	}
}

func TestChromeQUICNativeSessionResumption(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		t.Run(fmt.Sprintf("HRR=%v", hrr), func(t *testing.T) {
			clientConf, serverConf := getTLSConfigs()
			clientConf.NextProtos, serverConf.NextProtos = []string{"h3"}, []string{"h3"}
			if hrr {
				serverConf.CurvePreferences = []tls.CurveID{tls.CurveP256}
			}
			cache := newChromeSessionCache()
			cold, err := runChromeHandshake(t, clientConf, serverConf, cache)
			require.NoError(t, err)
			assertChromeHandshake(t, cold, false, hrr)
			require.Equal(t, int32(1), cache.puts.Load())
			require.Zero(t, cache.earlyStores.Load())
			// Model a caller-provided early-data cache entry, independently of
			// the store policy. ResumeSession must still clear EarlyData.
			cached, ok := cache.ClientSessionCache.Get("localhost")
			require.True(t, ok)
			_, session, err := cached.ResumptionState()
			require.NoError(t, err)
			session.EarlyData = true
			warm, err := runChromeHandshake(t, clientConf, serverConf, cache)
			require.NoError(t, err)
			assertChromeHandshake(t, warm, true, hrr)
			require.Equal(t, int32(2), cache.puts.Load())
			require.Positive(t, cache.hits.Load())
			require.Zero(t, cache.earlyStores.Load())
		})
	}
}

func TestChromeQUICResumptionControls(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	clientConf.NextProtos, serverConf.NextProtos = []string{"h3"}, []string{"h3"}
	cache := newChromeSessionCache()
	cold, err := runChromeHandshake(t, clientConf, serverConf, cache)
	require.NoError(t, err)
	assertChromeHandshake(t, cold, false, false)
	for _, test := range []struct {
		name     string
		cache    utls.ClientSessionCache
		disabled bool
	}{
		{"nil_native_cache", nil, false},
		{"distinct_empty_cache", newChromeSessionCache(), false},
		{"tickets_disabled_warm_cache", cache, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := clientConf.Clone()
			conf.SessionTicketsDisabled = test.disabled
			conf.ClientSessionCache = tls.NewLRUClientSessionCache(4) // never bridged
			result, err := runChromeHandshake(t, conf, serverConf, test.cache)
			require.NoError(t, err)
			assertChromeHandshake(t, result, false, false)
			coldIDs, newIDs := slices.Clone(cold.hellos[0].ids), slices.Clone(result.hellos[0].ids)
			slices.Sort(coldIDs)
			slices.Sort(newIDs)
			require.Equal(t, coldIDs, newIDs)
		})
	}
	// A ticket issued by another key is offered, then rejected safely by TLS.
	serverConf.SetSessionTicketKeys([][32]byte{{1, 2, 3, 4}})
	result, err := runChromeHandshake(t, clientConf, serverConf, cache)
	require.NoError(t, err)
	require.Contains(t, result.hellos[0].extensions, uint16(41))
	require.False(t, result.client.DidResume)
	require.False(t, result.server.DidResume)
	require.NotEmpty(t, result.client.VerifiedChains)
}

func TestChromeQUICCryptoSetupResumptionNeverEnables0RTT(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	clientConf.NextProtos, serverConf.NextProtos = []string{"h3"}, []string{"h3"}
	cache := newChromeSessionCache()
	for _, warm := range []bool{false, true} {
		client, err := NewCryptoSetupClient(
			protocol.ConnectionID{}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
			clientConf, true, true, cache, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1,
		)
		require.NoError(t, err)
		defer client.Close()
		var resetToken protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			protocol.ConnectionID{}, &net.UDPAddr{IP: net.IPv6loopback, Port: 1234}, &net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
			&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &resetToken},
			serverConf, true, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1,
		)
		defer server.Close()
		clientEvents, clientErr, serverEvents, serverErr := handshake(t, client, server)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		require.Equal(t, warm, client.ConnectionState().DidResume)
		require.Equal(t, warm, server.ConnectionState().DidResume)
		require.False(t, client.ConnectionState().Used0RTT)
		require.False(t, server.ConnectionState().Used0RTT)
		cs := client.(*cryptoSetup)
		require.False(t, cs.allow0RTT)
		require.Nil(t, cs.zeroRTTSealer)
		require.Nil(t, cs.zeroRTTParameters)
		for _, event := range append(clientEvents, serverEvents...) {
			require.NotEqual(t, EventReceived0RTTReadKeys, event.Kind)
			require.NotEqual(t, EventRestoredTransportParameters, event.Kind)
		}
	}
}

func TestChromeQUICResumptionVerification(t *testing.T) {
	for _, wrong := range []string{"roots", "hostname"} {
		t.Run(wrong, func(t *testing.T) {
			clientConf, serverConf := getTLSConfigs()
			clientConf.NextProtos, serverConf.NextProtos = []string{"h3"}, []string{"h3"}
			cache := newChromeSessionCache()
			_, err := runChromeHandshake(t, clientConf, serverConf, cache)
			require.NoError(t, err)
			conf := clientConf.Clone()
			if wrong == "roots" {
				conf.RootCAs = x509.NewCertPool()
			} else {
				conf.ServerName = "not-localhost.invalid"
			}
			result, err := runChromeHandshake(t, conf, serverConf, cache)
			require.Error(t, err)
			require.False(t, result.client.HandshakeComplete)
			var alert tls.AlertError
			require.ErrorAs(t, err, &alert)
			if wrong == "roots" {
				var unknown x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknown)
			}
		})
	}
}

func TestChromeQUICUnsupportedPolicies(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{"VerifyConnection", func(c *tls.Config) { c.VerifyConnection = func(tls.ConnectionState) error { return nil } }},
		{"GetConfigForClient", func(c *tls.Config) {
			c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
		}},
		{"GetCertificate", func(c *tls.Config) {
			c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
		}},
		{"StaticCertificates", func(c *tls.Config) { c.Certificates = []tls.Certificate{{}} }},
		{"RealECHWithResumption", func(c *tls.Config) { c.EncryptedClientHelloConfigList = []byte{0, 1} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConf, _ := getTLSConfigs()
			test.mutate(clientConf)
			conn, err := newUTLSQUICClient(clientConf, newChromeSessionCache())
			require.Error(t, err)
			require.Nil(t, conn)
		})
	}
}

// A tiny injected source makes otherwise unreachable store failures observable
// without changing session-cache semantics or requiring a malicious TLS peer.
type chromeEventSource struct {
	events   []utls.QUICEvent
	storeErr error
	stored   *utls.SessionState
}

func (*chromeEventSource) Start(context.Context) error                       { return nil }
func (*chromeEventSource) Close() error                                      { return nil }
func (*chromeEventSource) HandleData(utls.QUICEncryptionLevel, []byte) error { return nil }
func (*chromeEventSource) SetTransportParameters([]byte)                     {}
func (*chromeEventSource) ConnectionState() utls.ConnectionState { return utls.ConnectionState{} }

func (s *chromeEventSource) StoreSession(state *utls.SessionState) error {
	s.stored = state
	return s.storeErr
}

func (s *chromeEventSource) NextEvent() utls.QUICEvent {
	if len(s.events) == 0 {
		return utls.QUICEvent{Kind: utls.QUICNoEvent}
	}
	e := s.events[0]
	s.events = s.events[1:]
	return e
}

func TestChromeQUICSessionEventSafety(t *testing.T) {
	storeFailure := errors.New("test store failure")
	for _, test := range []struct {
		name     string
		event    utls.QUICEvent
		storeErr error
		enabled  bool
	}{
		{"store_error", utls.QUICEvent{Kind: utls.QUICStoreSession, SessionState: &utls.SessionState{EarlyData: true}}, storeFailure, true},
		{"nil_store", utls.QUICEvent{Kind: utls.QUICStoreSession}, nil, true},
		{"nil_resume", utls.QUICEvent{Kind: utls.QUICResumeSession}, nil, true},
		{"disabled_resume", utls.QUICEvent{Kind: utls.QUICResumeSession, SessionState: &utls.SessionState{}}, nil, false},
		{"early_read", utls.QUICEvent{Kind: utls.QUICSetReadSecret, Level: utls.QUICEncryptionLevelEarly}, nil, true},
		{"early_write", utls.QUICEvent{Kind: utls.QUICSetWriteSecret, Level: utls.QUICEncryptionLevelEarly}, nil, true},
		{"early_data", utls.QUICEvent{Kind: utls.QUICWriteData, Level: utls.QUICEncryptionLevelEarly}, nil, true},
		{"native_error", utls.QUICEvent{Kind: utls.QUICErrorEvent, Err: fmt.Errorf("peer failure: %w", utls.AlertError(42))}, nil, true},
		{"empty_error", utls.QUICEvent{Kind: utls.QUICErrorEvent}, nil, true},
		{"unknown_event", utls.QUICEvent{Kind: utls.QUICEventKind(999)}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &chromeEventSource{events: []utls.QUICEvent{test.event}, storeErr: test.storeErr}
			conn := &utlsQUICConn{conn: source, resumptionEnabled: test.enabled}
			ev := conn.NextEvent()
			require.Equal(t, tls.QUICErrorEvent, ev.Kind)
			require.Error(t, ev.Err)
			if test.storeErr != nil {
				require.ErrorIs(t, ev.Err, test.storeErr)
				require.NotNil(t, source.stored)
				require.False(t, source.stored.EarlyData)
			}
			if test.name == "native_error" {
				var alert tls.AlertError
				require.ErrorAs(t, ev.Err, &alert)
				require.Equal(t, tls.AlertError(42), alert)
			}
		})
	}
	resume, store := &utls.SessionState{EarlyData: true}, &utls.SessionState{EarlyData: true}
	source := &chromeEventSource{events: []utls.QUICEvent{{Kind: utls.QUICResumeSession, SessionState: resume}, {Kind: utls.QUICStoreSession, SessionState: store}, {Kind: utls.QUICHandshakeDone}}}
	conn := &utlsQUICConn{conn: source, resumptionEnabled: true}
	require.Equal(t, tls.QUICHandshakeDone, conn.NextEvent().Kind)
	require.False(t, resume.EarlyData)
	require.False(t, store.EarlyData)
	require.Same(t, store, source.stored)
}

func TestChromeQUICClosePendingResume(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	clientConf.NextProtos, serverConf.NextProtos = []string{"h3"}, []string{"h3"}
	cache := newChromeSessionCache()
	_, err := runChromeHandshake(t, clientConf, serverConf, cache)
	require.NoError(t, err)
	for _, cancelFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelFirst), func(t *testing.T) {
			client, err := newUTLSQUICClient(clientConf, cache)
			require.NoError(t, err)
			client.SetTransportParameters(chromeTestClientTP)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, client.Start(ctx)) // blocks at the native ResumeSession event
			if cancelFirst {
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- client.Close() }()
			select {
			case err := <-done:
				require.ErrorIs(t, err, tls.AlertError(0)) // close_notify
			case <-time.After(time.Second):
				t.Fatal("Close blocked with an undrained session event")
			}
		})
	}
	t.Run("canceled_event_drain", func(t *testing.T) {
		client, err := newUTLSQUICClient(clientConf, cache)
		require.NoError(t, err)
		defer client.Close()
		client.SetTransportParameters(chromeTestClientTP)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, client.Start(ctx))
		cancel()
		// The internally consumed ResumeSession must not release ClientHello
		// or secrets after cancellation, and the native error is not swallowed.
		ev := client.NextEvent()
		require.Equal(t, tls.QUICErrorEvent, ev.Kind)
		require.ErrorIs(t, ev.Err, tls.AlertError(0))
		require.Equal(t, tls.QUICNoEvent, client.NextEvent().Kind)
	})
}
