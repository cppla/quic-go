module github.com/apernet/quic-go

go 1.27.2

// Preserve the shared uTLS module identity. See FORK.md for the maintained patch queue.
replace github.com/refraction-networking/utls => github.com/cppla/utls v0.0.0-20261009031926-14c2a4cb1403

require (
	github.com/quic-go/go-ossfuzz-seeds v0.1.0
	github.com/quic-go/qpack v0.6.0
	github.com/refraction-networking/utls v1.8.3-0.20261006222701-ff1b50fbbe9a
	github.com/stretchr/testify v1.12.1
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/jordanlewis/gcassert v0.0.0-20250430164644-389ef753e22e // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
)

tool (
	github.com/jordanlewis/gcassert/cmd/gcassert
	go.uber.org/mock/mockgen
)
