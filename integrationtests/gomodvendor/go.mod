module test

go 1.27.2

replace github.com/refraction-networking/utls => github.com/cppla/utls v0.0.0-20261009031926-14c2a4cb1403

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/apernet/quic-go v0.21.0

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20261006222701-ff1b50fbbe9a // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/apernet/quic-go => ../../
