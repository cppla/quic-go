package quic

import (
	"fmt"
	mrand "math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestCryptoStreamDataAssembly(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}))
	// receive a retransmission
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))

	var data []byte
	for {
		b := str.GetCryptoData()
		if b == nil {
			break
		}
		data = append(data, b...)
	}
	require.Equal(t, []byte("foobar"), data)
}

func TestCryptoStreamMaxOffset(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{
		Offset: protocol.MaxCryptoStreamOffset - 5,
		Data:   []byte("foo"),
	}))
	require.ErrorIs(t,
		str.HandleCryptoFrame(&wire.CryptoFrame{
			Offset: protocol.MaxCryptoStreamOffset - 2,
			Data:   []byte("bar"),
		}),
		&qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded},
	)
}

func TestCryptoStreamFinishWithQueuedData(t *testing.T) {
	t.Run("with data at current offset", func(t *testing.T) {
		str := newCryptoStream()
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}))
		require.Equal(t, []byte("foo"), str.GetCryptoData())
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
		require.ErrorIs(t, str.Finish(), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})

	t.Run("with data at a higher offset", func(t *testing.T) {
		str := newCryptoStream()
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foobar"), Offset: 20}))
		require.ErrorIs(t, str.Finish(), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})
}

func TestCryptoStreamReceiveDataAfterFinish(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foobar")}))
	require.Equal(t, []byte("foobar"), str.GetCryptoData())
	require.NoError(t, str.Finish())
	// receiving a retransmission is ok
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
	// but receiving new data is not
	require.ErrorIs(t,
		str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("baz"), Offset: 4}),
		&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
	)
}

func expectedCryptoFrameLen(offset protocol.ByteCount) protocol.ByteCount {
	f := &wire.CryptoFrame{Offset: offset}
	return f.Length(protocol.Version1)
}

func TestCryptoStreamTailPreservesLaterFlightOffset(t *testing.T) {
	for _, appendBeforeDrain := range []bool{false, true} {
		t.Run(fmt.Sprintf("appendBeforeDrain=%v", appendBeforeDrain), func(t *testing.T) {
			stream := newInitialCryptoStream(true, true)
			// Ensure a later append could reuse the original backing array.
			// Without capacity clipping, this overwrites the returned tail.
			stream.writeBuf = make([]byte, 0, 64)
			_, err := stream.Write([]byte("first-hello"))
			require.NoError(t, err)
			tail := stream.PopCryptoFrameTail(5)
			require.Equal(t, protocol.ByteCount(6), tail.Offset)
			require.Equal(t, []byte("hello"), tail.Data)
			require.Nil(t, stream.PopCryptoFrameTail(1), "only one pending split is allowed")
			if appendBeforeDrain {
				_, err = stream.Write([]byte("second-hello"))
				require.NoError(t, err)
			}
			first := stream.PopCryptoFrame(1000)
			require.Equal(t, protocol.ByteCount(0), first.Offset)
			require.Equal(t, []byte("first-"), first.Data)
			require.Equal(t, protocol.ByteCount(11), stream.WriteOffset())
			if !appendBeforeDrain {
				_, err = stream.Write([]byte("second-hello"))
				require.NoError(t, err)
			}
			second := stream.PopCryptoFrame(1000)
			require.Equal(t, protocol.ByteCount(11), second.Offset)
			require.Equal(t, []byte("second-hello"), second.Data)
			require.Equal(t, []byte("hello"), tail.Data, "later writes must not mutate an in-flight tail")
			require.Equal(t, protocol.ByteCount(23), stream.WriteOffset())
			require.False(t, stream.HasData())
		})
	}
	t.Run("whole-buffer-tail", func(t *testing.T) {
		stream := newInitialCryptoStream(true, true)
		_, err := stream.Write([]byte("first"))
		require.NoError(t, err)
		tail := stream.PopCryptoFrameTail(5)
		require.Equal(t, protocol.ByteCount(0), tail.Offset)
		require.Equal(t, protocol.ByteCount(5), stream.WriteOffset())
		_, err = stream.Write([]byte("second"))
		require.NoError(t, err)
		require.Equal(t, []byte("first"), tail.Data)
		require.Equal(t, protocol.ByteCount(5), stream.PopCryptoFrame(1000).Offset)
	})
}

func TestCryptoStreamWrite(t *testing.T) {
	str := newCryptoStream()

	require.False(t, str.HasData())
	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)
	require.True(t, str.HasData())
	_, err = str.Write([]byte("bar"))
	require.NoError(t, err)
	_, err = str.Write([]byte("baz"))
	require.NoError(t, err)
	require.True(t, str.HasData())

	for i := range expectedCryptoFrameLen(0) {
		require.Nil(t, str.PopCryptoFrame(i))
	}

	f := str.PopCryptoFrame(expectedCryptoFrameLen(0) + 1)
	require.Equal(t, &wire.CryptoFrame{Data: []byte("f")}, f)
	require.True(t, str.HasData())
	f = str.PopCryptoFrame(expectedCryptoFrameLen(1) + 3)
	// the three write calls were coalesced into a single frame
	require.Equal(t, &wire.CryptoFrame{Offset: 1, Data: []byte("oob")}, f)
	f = str.PopCryptoFrame(protocol.MaxByteCount)
	require.Equal(t, &wire.CryptoFrame{Offset: 4, Data: []byte("arbaz")}, f)
	require.False(t, str.HasData())
}

func TestInitialCryptoStreamServer(t *testing.T) {
	str := newInitialCryptoStream(false, false)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	f := str.PopCryptoFrame(expectedCryptoFrameLen(0) + 3)
	require.Equal(t, &wire.CryptoFrame{Offset: 0, Data: []byte("foo")}, f)
	require.True(t, str.HasData())

	// append another CRYPTO frame to the existing slice
	f = str.PopCryptoFrame(expectedCryptoFrameLen(3) + 3)
	require.Equal(t, &wire.CryptoFrame{Offset: 3, Data: []byte("bar")}, f)
	require.False(t, str.HasData())
}

func reassembleCryptoData(t *testing.T, segments map[protocol.ByteCount][]byte) []byte {
	t.Helper()

	var reassembled []byte
	var offset protocol.ByteCount
	for len(segments) > 0 {
		b, ok := segments[offset]
		if !ok {
			break
		}
		reassembled = append(reassembled, b...)
		delete(segments, offset)
		offset = protocol.ByteCount(len(reassembled))
	}
	require.Empty(t, segments)
	return reassembled
}

func skipIfDisableScramblingEnvSet(t *testing.T) {
	t.Helper()
	disabled, err := strconv.ParseBool(os.Getenv(disableClientHelloScramblingEnv))
	if err == nil && disabled {
		t.Skip("ClientHello scrambling disabled via " + disableClientHelloScramblingEnv)
	}
}

func TestInitialCryptoStreamClientStatic(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	str := newInitialCryptoStream(true, false)
	clientHello, err := getClientHello("quic-go.net")
	require.NoError(t, err)
	_, err = str.Write(clientHello)
	require.NoError(t, err)
	require.True(t, str.HasData())
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)

	segments := make(map[protocol.ByteCount][]byte)

	f1 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f1)
	segments[f1.Offset] = f1.Data
	require.True(t, str.HasData())

	f2 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f2)
	require.NotContains(t, segments, f2.Offset)
	segments[f2.Offset] = f2.Data
	require.True(t, str.HasData())
	require.NotEqual(t, f2.Offset, protocol.ByteCount(len(f1.Data)))

	f3 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f2)
	require.NotContains(t, segments, f3.Offset)
	segments[f3.Offset] = f3.Data
	require.True(t, str.HasData())
	require.NotEqual(t, f3.Offset, protocol.ByteCount(len(f2.Data)))

	f4 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f4)
	require.NotContains(t, segments, f4.Offset)
	segments[f4.Offset] = f4.Data
	require.Equal(t, []byte("foobar"), f4.Data)
	require.False(t, str.HasData())
	require.NotEqual(t, f4.Offset, protocol.ByteCount(len(f3.Data)))

	reassembled := reassembleCryptoData(t, segments)
	require.Equal(t, append(clientHello, []byte("foobar")...), reassembled)
}

func randomDomainName(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		if i > 0 && i < length-1 && mrand.IntN(5) == 0 && b[i-1] != '.' {
			b[i] = '.'
		} else {
			b[i] = alphabet[mrand.IntN(len(alphabet))]
		}
	}
	return string(b)
}

func TestInitialCryptoStreamClientRandomizedSizes(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	for i := range 100 {
		t.Run(fmt.Sprintf("run %d", i), func(t *testing.T) {
			var serverName string
			if mrand.Int()%4 > 0 {
				serverName = randomDomainName(6 + mrand.IntN(20))
			}
			var clientHello []byte
			if serverName == "" || !strings.Contains(serverName, ".") || mrand.Int()%2 == 0 {
				t.Logf("using a ClientHello without ECH, hostname: %q", serverName)
				var err error
				clientHello, err = getClientHello(serverName)
				require.NoError(t, err)
			} else {
				t.Logf("using a ClientHello with ECH, hostname: %q", serverName)
				var err error
				clientHello, err = getClientHelloWithECH(serverName)
				require.NoError(t, err)
			}
			testInitialCryptoStreamClientRandomizedSizes(t, clientHello, serverName)
		})
	}
}

func testInitialCryptoStreamClientRandomizedSizes(t *testing.T, clientHello []byte, expectedServerName string) {
	str := newInitialCryptoStream(true, false)

	b := slices.Clone(clientHello)
	for len(b) > 0 {
		n := min(len(b), mrand.IntN(2*len(b)))
		_, err := str.Write(b[:n])
		require.NoError(t, err)
		b = b[n:]
	}

	require.True(t, str.HasData())
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	segments := make(map[protocol.ByteCount][]byte)

	var frames []*wire.CryptoFrame
	for str.HasData() {
		// fmt.Println("popping a frame")
		var maxSize protocol.ByteCount
		if mrand.Int()%4 == 0 {
			maxSize = protocol.ByteCount(mrand.IntN(512) + 1)
		} else {
			maxSize = protocol.ByteCount(mrand.IntN(32) + 1)
		}
		f := str.PopCryptoFrame(maxSize)
		if f == nil {
			continue
		}
		frames = append(frames, f)
		require.LessOrEqual(t, f.Length(protocol.Version1), maxSize)
	}
	t.Logf("received %d frames", len(frames))

	for _, f := range frames {
		t.Logf("offset %d: %d bytes", f.Offset, len(f.Data))
		if expectedServerName != "" {
			require.NotContainsf(t, string(f.Data), expectedServerName, "frame at offset %d contains the server name", f.Offset)
		}
		segments[f.Offset] = f.Data
	}

	reassembled := reassembleCryptoData(t, segments)
	require.Equal(t, append(clientHello, []byte("foobar")...), reassembled)
	if expectedServerName != "" {
		require.Contains(t, string(reassembled), expectedServerName)
	}
}
