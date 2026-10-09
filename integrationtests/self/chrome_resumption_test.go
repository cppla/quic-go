package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/internal/testdata"
	"github.com/apernet/quic-go/testutils/simnet"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

type chromePacketSessionCache struct {
	utls.ClientSessionCache
	stored chan bool
}

func (c *chromePacketSessionCache) Put(key string, state *utls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		_, session, err := state.ResumptionState()
		c.stored <- err == nil && session != nil && !session.EarlyData
	}
}

// Observe real encrypted QUIC datagrams on a deterministic simulated link.
// This covers the Config/Transport/packet pipeline in addition to the adapter's
// ClientHello tests, including the public DialEarly entry point.
func TestChromeSessionResumptionNeverSends0RTTPackets(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		t.Run(fmt.Sprintf("HRR=%v", hrr), func(t *testing.T) {
			// The general integration fixture uses Ed25519, which this fixed
			// browser profile doesn't advertise. Use the RSA localhost fixture
			// and its real validation time while synctest advances link time.
			validationTime := time.Now()
			serverTLS := testdata.GetTLSConfig()
			serverTLS.NextProtos = []string{"h3"}
			serverTLS.Time = func() time.Time { return validationTime }
			clientTLS := &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: []string{"h3"}, Time: func() time.Time { return validationTime }}
			if hrr {
				serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP256}
			}
			synctest.Test(t, func(t *testing.T) {
				router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
				clientPacket, serverPacket, closeLink := newSimnetLinkWithRouter(t, 20*time.Millisecond, router)
				defer closeLink(t)
				serverTransport := &quic.Transport{Conn: serverPacket}
				defer serverTransport.Close()
				listener, err := serverTransport.ListenEarly(serverTLS, getQuicConfig(&quic.Config{Versions: []quic.Version{quic.Version1}, Allow0RTT: true}))
				require.NoError(t, err)
				defer listener.Close()
				clientTransport := &quic.Transport{Conn: clientPacket}
				defer clientTransport.Close()
				cache := &chromePacketSessionCache{ClientSessionCache: utls.NewLRUClientSessionCache(4), stored: make(chan bool, 8)}
				clientConfig := getQuicConfig(&quic.Config{Versions: []quic.Version{quic.Version1}, ChromeParrot: true, ChromeParrotSessionCache: cache})
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				for _, warm := range []bool{false, true} {
					client, err := clientTransport.DialEarly(ctx, listener.Addr(), clientTLS, clientConfig)
					require.NoError(t, err)
					defer client.CloseWithError(0, "")
					select {
					case <-client.HandshakeComplete():
					default:
						t.Fatal("Chrome DialEarly returned before handshake completion")
					}
					server, err := listener.Accept(ctx)
					require.NoError(t, err)
					defer server.CloseWithError(0, "")
					select {
					case <-server.HandshakeComplete():
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					require.Equal(t, warm, client.ConnectionState().TLS.DidResume)
					require.Equal(t, warm, server.ConnectionState().TLS.DidResume)
					require.NotEmpty(t, client.ConnectionState().TLS.VerifiedChains)
					require.False(t, client.ConnectionState().Used0RTT)
					require.False(t, server.ConnectionState().Used0RTT)
					stream, err := client.OpenUniStreamSync(ctx)
					require.NoError(t, err)
					payload := []byte("application phase after TLS completion")
					_, err = stream.Write(payload)
					require.NoError(t, err)
					require.NoError(t, stream.Close())
					incoming, err := server.AcceptUniStream(ctx)
					require.NoError(t, err)
					got, err := io.ReadAll(incoming)
					require.NoError(t, err)
					require.Equal(t, payload, got)
					select {
					case earlyDisabled := <-cache.stored:
						require.True(t, earlyDisabled, "ticket persisted with EarlyData enabled")
					case <-ctx.Done():
						t.Fatal("real ticket was not stored before reconnect")
					}
					require.NoError(t, client.CloseWithError(0, ""))
					select {
					case <-server.Context().Done():
					case <-ctx.Done():
						t.Fatal("previous physical connection did not close")
					}
				}
				require.Zero(t, router.Num0RTTPackets(), "no 0-RTT packets, including coalesced packets, may reach the link")
			})
		})
	}
}
