/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/protolator"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	. "github.com/onsi/gomega"
)

func bidirectionalMarshal(t *testing.T, doc proto.Message) {
	gt := NewGomegaWithT(t)

	var buffer bytes.Buffer

	err := protolator.DeepMarshalJSON(&buffer, doc)
	gt.Expect(err).NotTo(HaveOccurred())

	newRoot := proto.Clone(doc)
	newRoot.Reset()
	err = protolator.DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newRoot)
	gt.Expect(err).NotTo(HaveOccurred())

	// Note, we cannot do an equality check between newRoot and sampleDoc
	// because of the nondeterministic nature of binary proto marshaling
	// So instead we re-marshal to JSON which is a deterministic marshaling
	// and compare equality there instead

	//t.Log(doc)
	//t.Log(newRoot)

	var remarshaled bytes.Buffer
	err = protolator.DeepMarshalJSON(&remarshaled, newRoot)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(remarshaled.String()).To(Equal(buffer.String()))
	//t.Log(buffer.String())
	//t.Log(remarshaled.String())
}

func TestConfigUpdate(t *testing.T) {
	gt := NewGomegaWithT(t)

	blockBin, err := ioutil.ReadFile("testdata/block.pb")
	gt.Expect(err).NotTo(HaveOccurred())

	block := &cb.Block{}
	err = proto.Unmarshal(blockBin, block)
	gt.Expect(err).NotTo(HaveOccurred())

	envelope := &cb.Envelope{}
	err = proto.Unmarshal(block.Data.Data[0], envelope)
	gt.Expect(err).NotTo(HaveOccurred())

	blockDataPayload := &cb.Payload{}
	err = proto.Unmarshal(envelope.Payload, blockDataPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(blockDataPayload.Data, config)
	gt.Expect(err).NotTo(HaveOccurred())

	bidirectionalMarshal(t, &cb.ConfigUpdateEnvelope{
		ConfigUpdate: protoMarshalOrPanic(&cb.ConfigUpdate{
			ReadSet:  config.Config.ChannelGroup,
			WriteSet: config.Config.ChannelGroup,
		}),
	})
}

func TestIdemix(t *testing.T) {
	bidirectionalMarshal(t, &mb.MSPConfig{
		Type: 1,
		Config: protoMarshalOrPanic(&mb.IdemixMSPConfig{
			Name: "fooo",
		}),
	})
}

func TestBlock(t *testing.T) {
	gt := NewGomegaWithT(t)

	blockBin, err := ioutil.ReadFile("testdata/block.pb")
	gt.Expect(err).NotTo(HaveOccurred())

	block := &cb.Block{}
	err = proto.Unmarshal(blockBin, block)
	gt.Expect(err).NotTo(HaveOccurred())

	bidirectionalMarshal(t, block)
}

func TestEmitDefaultsBug(t *testing.T) {
	gt := NewGomegaWithT(t)

	block := &cb.Block{
		Header: &cb.BlockHeader{
			PreviousHash: []byte("foo"),
		},
		Data: &cb.BlockData{
			Data: [][]byte{
				protoMarshalOrPanic(&cb.Envelope{
					Payload: protoMarshalOrPanic(&cb.Payload{
						Header: &cb.Header{
							ChannelHeader: protoMarshalOrPanic(&cb.ChannelHeader{
								Type: int32(cb.HeaderType_CONFIG),
							}),
						},
					}),
					Signature: []byte("bar"),
				}),
			},
		},
	}

	buf := &bytes.Buffer{}
	err := protolator.DeepMarshalJSON(buf, block)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(buf.String()).To(MatchJSON(`
{
	"data": {
		"data": [
			{
				"payload": {
					"data": null,
					"header": {
						"channel_header": {
							"channel_id": "",
							"epoch": "0",
							"extension": null,
							"timestamp": null,
							"tls_cert_hash": null,
							"tx_id": "",
							"type": 1,
							"version": 0
						},
						"signature_header": null
					}
				},
				"signature": "YmFy"
			}
		]
	},
	"header": {
		"data_hash": null,
		"number": "0",
		"previous_hash": "Zm9v"
	},
	"metadata": null
}
`))
}

func TestProposalResponsePayload(t *testing.T) {
	gt := NewGomegaWithT(t)

	prp := &pb.ProposalResponsePayload{}
	err := protolator.DeepUnmarshalJSON(bytes.NewReader([]byte(`{
            "extension": {
              "chaincode_id": {
                "name": "test",
                "path": "",
                "version": "1.0"
              },
              "events": {
                  "chaincode_id": "test"
              },
              "response": {
                "message": "",
                "payload": null,
                "status": 200
              },
              "results": {
                "data_model": "KV",
                "ns_rwset": [
                  {
                    "collection_hashed_rwset": [],
                    "namespace": "lscc",
                    "rwset": {
                      "metadata_writes": [],
                      "range_queries_info": [],
                      "reads": [
                        {
                          "key": "cc1",
                          "version": {
                            "block_num": "3",
                            "tx_num": "0"
                          }
                        },
                        {
                          "key": "cc2",
                          "version": {
                            "block_num": "4",
                            "tx_num": "0"
                          }
                        }
                      ],
                      "writes": []
                    }
                  },
                  {
                    "collection_hashed_rwset": [],
                    "namespace": "cc1",
                    "rwset": {
                      "metadata_writes": [],
                      "range_queries_info": [],
                      "reads": [
                        {
                          "key": "key1",
                          "version": {
                            "block_num": "8",
                            "tx_num": "0"
                          }
                        }
                      ],
                      "writes": [
                        {
                          "is_delete": false,
                          "key": "key2"
                        }
                      ]
                    }
                  },
                  {
                    "collection_hashed_rwset": [],
                    "namespace": "cc2",
                    "rwset": {
                      "metadata_writes": [],
                      "range_queries_info": [],
                      "reads": [
                        {
                          "key": "key1",
                          "version": {
                            "block_num": "9",
                            "tx_num": "0"
                          }
                        },
                        {
                          "key": "key2",
                          "version": {
                            "block_num": "10",
                            "tx_num": "0"
                          }
                        }
                      ],
                      "writes": [
                        {
                          "is_delete": false,
                          "key": "key1"
                        },
                        {
                          "is_delete": true,
                          "key": "key2"
                        }
                      ]
                    }
                  }
                ]
              }
            }
        }`)), prp)
	gt.Expect(err).NotTo(HaveOccurred())
	bidirectionalMarshal(t, prp)
}

func TestChannelCreationPolicy(t *testing.T) {
	cu := &cb.ConfigUpdate{
		WriteSet: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Consortiums": {
					Groups: map[string]*cb.ConfigGroup{
						"SampleConsortium": {
							Values: map[string]*cb.ConfigValue{
								"ChannelCreationPolicy": {
									Version: 0,
								},
							},
						},
					},
				},
			},
		},
	}

	bidirectionalMarshal(t, cu)
}

func TestStaticMarshal(t *testing.T) {
	gt := NewGomegaWithT(t)

	// To generate artifacts:
	// e.g.
	//  FABRICPATH=$GOPATH/src/github.com/hyperledger/fabric
	// 	configtxgen -channelID test -outputBlock block.pb -profile SampleSingleMSPSolo -configPath FABRICPATH/sampleconfig
	// 	configtxgen -configPath FABRICPATH/sampleconfig -inspectBlock block.pb > block.json

	blockBin, err := ioutil.ReadFile("testdata/block.pb")
	gt.Expect(err).NotTo(HaveOccurred())

	block := &cb.Block{}
	err = proto.Unmarshal(blockBin, block)
	gt.Expect(err).NotTo(HaveOccurred())

	jsonBin, err := ioutil.ReadFile("testdata/block.json")
	gt.Expect(err).NotTo(HaveOccurred())

	buf := &bytes.Buffer{}
	err = protolator.DeepMarshalJSON(buf, block)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(buf).To(MatchJSON(jsonBin))
}

// protoMarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func protoMarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}

	return data
}
