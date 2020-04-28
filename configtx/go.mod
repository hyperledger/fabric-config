module github.com/hyperledger/fabric-config/configtx

go 1.14

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/golang/protobuf v1.4.0
	github.com/hyperledger/fabric-config/protolator v0.0.0-00010101000000-000000000000
	github.com/hyperledger/fabric-protos-go v0.0.0-20200424173316-dd554ba3746e
	github.com/onsi/gomega v1.9.0
)

replace github.com/hyperledger/fabric-config/protolator => ../protolator
