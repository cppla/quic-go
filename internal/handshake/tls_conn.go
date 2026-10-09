package handshake

import (
	"context"
	"crypto/tls"
)

// tlsQUICConn abstracts the QUIC-TLS connection driven by cryptoSetup, so the
// client can be backed either by crypto/tls or, when parroting Chrome, by uTLS.
//
// crypto/tls's *tls.QUICConn satisfies this natively; uTLS is adapted in
// tls_conn_utls.go. Events are normalized to crypto/tls types, which works for
// every field except SessionState, whose internals are unexported and therefore
// not convertible between the two libraries. The uTLS adapter consumes its
// native session events internally and never exposes them through this interface.
type tlsQUICConn interface {
	Start(context.Context) error
	NextEvent() tls.QUICEvent
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	StoreSession(*tls.SessionState) error
	ConnectionState() tls.ConnectionState
	Close() error
}

var _ tlsQUICConn = (*tls.QUICConn)(nil)
