module github.com/apernet/quic-go/integrationtests/fips

go 1.27.2

replace github.com/refraction-networking/utls => github.com/cppla/utls v0.0.0-20261009031926-14c2a4cb1403

require (
	// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
	github.com/apernet/quic-go v0.60.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20261006222701-ff1b50fbbe9a // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/apernet/quic-go => ../../
