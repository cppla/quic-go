package quic

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/mocks"
	mockackhandler "github.com/apernet/quic-go/internal/mocks/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnectionMigrationSynchronizesPublicState(t *testing.T) {
	oldLocal := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	newLocal := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20001}
	updatedRemote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20002}

	for _, tt := range []struct {
		name string
		call func(*Conn) any
		want any
	}{
		{name: "LocalAddr", call: func(c *Conn) any { return c.LocalAddr().String() }, want: newLocal.String()},
		{name: "RemoteAddr", call: func(c *Conn) any { return c.RemoteAddr().String() }, want: remote.String()},
		{name: "ConnectionState", call: func(c *Conn) any { return c.ConnectionState().GSO }, want: true},
		{name: "SetRemoteAddr", call: func(c *Conn) any {
			c.SetRemoteAddr(updatedRemote)
			return c.RemoteAddr().String()
		}, want: updatedRemote.String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			oldRaw := NewMockRawConn(ctrl)
			oldRaw.EXPECT().LocalAddr().Return(oldLocal)
			oldRaw.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
			newRaw := NewMockRawConn(ctrl)
			newRaw.EXPECT().capabilities().Return(connCapabilities{GSO: true}).AnyTimes()
			constructing := make(chan struct{})
			allowConstruction := make(chan struct{})
			releaseConstruction := sync.OnceFunc(func() { close(allowConstruction) })
			defer releaseConstruction()
			newRaw.EXPECT().LocalAddr().DoAndReturn(func() net.Addr {
				close(constructing)
				<-allowConstruction
				return newLocal
			})
			crypto := mocks.NewMockCryptoSetup(ctrl)
			crypto.EXPECT().ConnectionState().Return(handshake.ConnectionState{}).AnyTimes()
			sentPackets := mockackhandler.NewMockSentPacketHandler(ctrl)
			sentPackets.EXPECT().MigratedPath(gomock.Any(), protocol.ByteCount(1200))
			oldQueue := NewMockSender(ctrl)
			c := &Conn{
				conn:                newSendConn(oldRaw, remote, packetInfo{}, utils.DefaultLogger),
				config:              &Config{InitialPacketSize: 1200},
				peerParams:          &wire.TransportParameters{},
				cryptoStreamHandler: crypto,
				sentPacketHandler:   sentPackets,
				mtuDiscoverer:       newMTUDiscoverer(utils.NewRTTStats(), 1200, 1452, nil),
				sendQueue:           oldQueue,
			}
			// Queue shutdown must happen after releasing the state lock: a
			// queue or its writer can still inspect the connection while closing.
			queueCloseAddress := make(chan net.Addr, 1)
			oldQueue.EXPECT().Close().Do(func() { queueCloseAddress <- c.LocalAddr() })
			switched := make(chan struct{})
			go func() {
				c.switchToNewPath(&Transport{conn: newRaw}, monotime.Now())
				close(switched)
			}()
			select {
			case <-constructing:
			case <-time.After(time.Second):
				t.Fatal("migration did not start constructing the new send connection")
			}

			started := make(chan struct{})
			result := make(chan any, 1)
			go func() {
				close(started)
				result <- tt.call(c)
			}()
			<-started
			// Hold migration at a known point, instead of sleeping to arrange
			// an overlap. A public call must wait for the new path to be published.
			var early any
			var completedEarly bool
			select {
			case early = <-result:
				completedEarly = true
			case <-time.After(25 * time.Millisecond):
			}
			releaseConstruction()
			select {
			case <-switched:
			case <-time.After(time.Second):
				t.Fatal("migration did not finish after releasing construction")
			}
			defer c.sendQueue.Close()
			require.Equal(t, newLocal, <-queueCloseAddress)
			if completedEarly {
				t.Fatalf("%s completed before the new send connection was published: %v", tt.name, early)
			}
			select {
			case got := <-result:
				require.Equal(t, tt.want, got)
			case <-time.After(time.Second):
				t.Fatal("public state operation did not finish after migration")
			}
			if tt.name == "SetRemoteAddr" {
				require.Equal(t, updatedRemote, c.RemoteAddr(), "migration must not lose a concurrent address update")
			}
		})
	}
}
