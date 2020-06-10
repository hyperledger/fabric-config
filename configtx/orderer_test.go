/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/ordererext"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestNewOrdererGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ordererType           string
		numOrdererGroupValues int
		expectedConfigJSONGen func(Orderer) string
	}{
		{
			ordererType:           orderer.ConsensusTypeSolo,
			numOrdererGroupValues: 5,
			expectedConfigJSONGen: func(o Orderer) string {
				certBase64, crlBase64 := certCRLBase64(t, o.Organizations[0].MSP)
				return fmt.Sprintf(`{
	"groups": {
		"OrdererOrg": {
			"groups": {},
			"mod_policy": "Admins",
			"policies": {
				"Admins": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
						}
					},
					"version": "0"
				},
				"Endorsement": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Endorsement"
						}
					},
					"version": "0"
				},
				"Readers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
						}
					},
					"version": "0"
				},
				"Writers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
						}
					},
					"version": "0"
				}
			},
			"values": {
				"Endpoints": {
					"mod_policy": "Admins",
					"value": {
						"addresses": [
							"localhost:123"
						]
					},
					"version": "0"
				},
				"MSP": {
					"mod_policy": "Admins",
					"value": {
						"config": {
							"admins": [
								"%[1]s"
							],
							"crypto_config": {
								"identity_identifier_hash_function": "SHA256",
								"signature_hash_family": "SHA3"
							},
							"fabric_node_ous": {
								"admin_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"client_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"enable": false,
								"orderer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"peer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							},
							"intermediate_certs": [
								"%[1]s"
							],
							"name": "MSPID",
							"organizational_unit_identifiers": [
								{
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							],
							"revocation_list": [
								"%[2]s"
							],
							"root_certs": [
								"%[1]s"
							],
							"signing_identity": null,
							"tls_intermediate_certs": [
								"%[1]s"
							],
							"tls_root_certs": [
								"%[1]s"
							]
						},
						"type": 0
					},
					"version": "0"
				}
			},
			"version": "0"
		}
	},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"BlockValidation": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"BatchSize": {
			"mod_policy": "Admins",
			"value": {
				"absolute_max_bytes": 100,
				"max_message_count": 100,
				"preferred_max_bytes": 100
			},
			"version": "0"
		},
		"BatchTimeout": {
			"mod_policy": "Admins",
			"value": {
				"timeout": "0s"
			},
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {
					"V1_3": {}
				}
			},
			"version": "0"
		},
		"ChannelRestrictions": {
			"mod_policy": "Admins",
			"value": {
				"max_count": "0"
			},
			"version": "0"
		},
		"ConsensusType": {
			"mod_policy": "Admins",
			"value": {
				"metadata": null,
				"state": "STATE_NORMAL",
				"type": "solo"
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, certBase64, crlBase64)
			},
		},
		{
			ordererType:           orderer.ConsensusTypeEtcdRaft,
			numOrdererGroupValues: 5,
			expectedConfigJSONGen: func(o Orderer) string {
				certBase64, crlBase64 := certCRLBase64(t, o.Organizations[0].MSP)
				etcdRaftCert := o.EtcdRaft.Consenters[0].ClientTLSCert
				etcdRaftCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(etcdRaftCert))
				return fmt.Sprintf(`{
	"groups": {
		"OrdererOrg": {
			"groups": {},
			"mod_policy": "Admins",
			"policies": {
				"Admins": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
						}
					},
					"version": "0"
				},
				"Endorsement": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Endorsement"
						}
					},
					"version": "0"
				},
				"Readers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
						}
					},
					"version": "0"
				},
				"Writers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
						}
					},
					"version": "0"
				}
			},
			"values": {
				"Endpoints": {
					"mod_policy": "Admins",
					"value": {
						"addresses": [
							"localhost:123"
						]
					},
					"version": "0"
				},
				"MSP": {
					"mod_policy": "Admins",
					"value": {
						"config": {
							"admins": [
								"%[1]s"
							],
							"crypto_config": {
								"identity_identifier_hash_function": "SHA256",
								"signature_hash_family": "SHA3"
							},
							"fabric_node_ous": {
								"admin_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"client_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"enable": false,
								"orderer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"peer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							},
							"intermediate_certs": [
								"%[1]s"
							],
							"name": "MSPID",
							"organizational_unit_identifiers": [
								{
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							],
							"revocation_list": [
								"%[2]s"
							],
							"root_certs": [
								"%[1]s"
							],
							"signing_identity": null,
							"tls_intermediate_certs": [
								"%[1]s"
							],
							"tls_root_certs": [
								"%[1]s"
							]
						},
						"type": 0
					},
					"version": "0"
				}
			},
			"version": "0"
		}
	},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"BlockValidation": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"BatchSize": {
			"mod_policy": "Admins",
			"value": {
				"absolute_max_bytes": 100,
				"max_message_count": 100,
				"preferred_max_bytes": 100
			},
			"version": "0"
		},
		"BatchTimeout": {
			"mod_policy": "Admins",
			"value": {
				"timeout": "0s"
			},
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {
					"V1_3": {}
				}
			},
			"version": "0"
		},
		"ChannelRestrictions": {
			"mod_policy": "Admins",
			"value": {
				"max_count": "0"
			},
			"version": "0"
		},
		"ConsensusType": {
			"mod_policy": "Admins",
			"value": {
				"metadata": {
					"consenters": [
						{
							"client_tls_cert": "%[3]s",
							"host": "node-1.example.com",
							"port": 7050,
							"server_tls_cert": "%[3]s"
						},
						{
							"client_tls_cert": "%[3]s",
							"host": "node-2.example.com",
							"port": 7050,
							"server_tls_cert": "%[3]s"
						},
						{
							"client_tls_cert": "%[3]s",
							"host": "node-3.example.com",
							"port": 7050,
							"server_tls_cert": "%[3]s"
						}
					],
					"options": {
						"election_tick": 0,
						"heartbeat_tick": 0,
						"max_inflight_blocks": 0,
						"snapshot_interval_size": 0,
						"tick_interval": ""
					}
				},
				"state": "STATE_NORMAL",
				"type": "etcdraft"
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, certBase64, crlBase64, etcdRaftCertBase64)
			},
		},
		{
			ordererType:           orderer.ConsensusTypeKafka,
			numOrdererGroupValues: 6,
			expectedConfigJSONGen: func(o Orderer) string {
				certBase64, crlBase64 := certCRLBase64(t, o.Organizations[0].MSP)
				return fmt.Sprintf(`{
	"groups": {
		"OrdererOrg": {
			"groups": {},
			"mod_policy": "Admins",
			"policies": {
				"Admins": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
						}
					},
					"version": "0"
				},
				"Endorsement": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Endorsement"
						}
					},
					"version": "0"
				},
				"Readers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
						}
					},
					"version": "0"
				},
				"Writers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
						}
					},
					"version": "0"
				}
			},
			"values": {
				"Endpoints": {
					"mod_policy": "Admins",
					"value": {
						"addresses": [
							"localhost:123"
						]
					},
					"version": "0"
				},
				"MSP": {
					"mod_policy": "Admins",
					"value": {
						"config": {
							"admins": [
								"%[1]s"
							],
							"crypto_config": {
								"identity_identifier_hash_function": "SHA256",
								"signature_hash_family": "SHA3"
							},
							"fabric_node_ous": {
								"admin_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"client_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"enable": false,
								"orderer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"peer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							},
							"intermediate_certs": [
								"%[1]s"
							],
							"name": "MSPID",
							"organizational_unit_identifiers": [
								{
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							],
							"revocation_list": [
								"%[2]s"
							],
							"root_certs": [
								"%[1]s"
							],
							"signing_identity": null,
							"tls_intermediate_certs": [
								"%[1]s"
							],
							"tls_root_certs": [
								"%[1]s"
							]
						},
						"type": 0
					},
					"version": "0"
				}
			},
			"version": "0"
		}
	},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"BlockValidation": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"BatchSize": {
			"mod_policy": "Admins",
			"value": {
				"absolute_max_bytes": 100,
				"max_message_count": 100,
				"preferred_max_bytes": 100
			},
			"version": "0"
		},
		"BatchTimeout": {
			"mod_policy": "Admins",
			"value": {
				"timeout": "0s"
			},
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {
					"V1_3": {}
				}
			},
			"version": "0"
		},
		"ChannelRestrictions": {
			"mod_policy": "Admins",
			"value": {
				"max_count": "0"
			},
			"version": "0"
		},
		"ConsensusType": {
			"mod_policy": "Admins",
			"value": {
				"metadata": null,
				"state": "STATE_NORMAL",
				"type": "kafka"
			},
			"version": "0"
		},
		"KafkaBrokers": {
			"mod_policy": "Admins",
			"value": {
				"brokers": [
					"broker1",
					"broker2"
				]
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, certBase64, crlBase64)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.ordererType, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			ordererConf, _ := baseOrdererOfType(t, tt.ordererType)

			ordererGroup, err := newOrdererGroup(ordererConf)
			gt.Expect(err).NotTo(HaveOccurred())
			expectedConfigJSON := tt.expectedConfigJSONGen(ordererConf)

			buf := bytes.Buffer{}
			err = protolator.DeepMarshalJSON(&buf, &ordererext.DynamicOrdererGroup{ConfigGroup: ordererGroup})
			gt.Expect(err).NotTo(HaveOccurred())
			gt.Expect(buf.String()).To(Equal(expectedConfigJSON))
		})
	}
}

func TestNewOrdererGroupFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName   string
		ordererMod func(*Orderer)
		err        string
	}{
		{
			testName: "When orderer group policy is empty",
			ordererMod: func(o *Orderer) {
				o.Policies = nil
			},
			err: "no policies defined",
		},
		{
			testName: "When orderer type is unknown",
			ordererMod: func(o *Orderer) {
				o.OrdererType = "ConsensusTypeGreen"
			},
			err: "unknown orderer type 'ConsensusTypeGreen'",
		},
		{
			testName: "When adding policies to orderer org group",
			ordererMod: func(o *Orderer) {
				o.Organizations[0].Policies = nil
			},
			err: "org group 'OrdererOrg': no policies defined",
		},
		{
			testName: "When missing consenters in EtcdRaft for consensus type etcdraft",
			ordererMod: func(o *Orderer) {
				o.OrdererType = orderer.ConsensusTypeEtcdRaft
				o.EtcdRaft = orderer.EtcdRaft{
					Consenters: nil,
				}
			},
			err: "marshaling etcdraft metadata for orderer type 'etcdraft': consenters are required",
		},
		{
			testName: "When missing a client tls cert in EtcdRaft for consensus type etcdraft",
			ordererMod: func(o *Orderer) {
				o.OrdererType = orderer.ConsensusTypeEtcdRaft
				o.EtcdRaft = orderer.EtcdRaft{
					Consenters: []orderer.Consenter{
						{
							Address: orderer.EtcdAddress{
								Host: "host1",
								Port: 123,
							},
							ClientTLSCert: nil,
						},
					},
				}
			},
			err: "marshaling etcdraft metadata for orderer type 'etcdraft': client tls cert for consenter host1:123 is required",
		},
		{
			testName: "When missing a server tls cert in EtcdRaft for consensus type etcdraft",
			ordererMod: func(o *Orderer) {
				o.OrdererType = orderer.ConsensusTypeEtcdRaft
				o.EtcdRaft = orderer.EtcdRaft{
					Consenters: []orderer.Consenter{
						{
							Address: orderer.EtcdAddress{
								Host: "host1",
								Port: 123,
							},
							ClientTLSCert: &x509.Certificate{},
							ServerTLSCert: nil,
						},
					},
				}
			},
			err: "marshaling etcdraft metadata for orderer type 'etcdraft': server tls cert for consenter host1:123 is required",
		},
		{
			testName: "When consensus state is invalid",
			ordererMod: func(o *Orderer) {
				o.State = "invalid state"
			},
			err: "unknown consensus state 'invalid state'",
		},
		{
			testName: "When consensus state is invalid",
			ordererMod: func(o *Orderer) {
				o.State = "invalid state"
			},
			err: "unknown consensus state 'invalid state'",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			ordererConf, _ := baseSoloOrderer(t)
			tt.ordererMod(&ordererConf)

			ordererGroup, err := newOrdererGroup(ordererConf)
			gt.Expect(err).To(MatchError(tt.err))
			gt.Expect(ordererGroup).To(BeNil())
		})
	}
}

func TestSetOrdererConfiguration(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	certBase64, crlBase64 := certCRLBase64(t, baseOrdererConf.Organizations[0].MSP)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	imp, err := implicitMetaFromString(baseOrdererConf.Policies[AdminsPolicyKey].Rule)
	gt.Expect(err).NotTo(HaveOccurred())

	originalAdminsPolicy, err := proto.Marshal(imp)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
			Values: map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{
				AdminsPolicyKey: {
					Policy: &cb.Policy{
						Type:  int32(cb.Policy_IMPLICIT_META),
						Value: originalAdminsPolicy,
					},
					ModPolicy: AdminsPolicyKey,
				},
			},
		},
	}

	updatedOrdererConf := baseOrdererConf

	// Modify MaxMessageCount and ConesnsusType to etcdraft
	updatedOrdererConf.BatchSize.MaxMessageCount = 10000
	updatedOrdererConf.OrdererType = orderer.ConsensusTypeEtcdRaft
	updatedOrdererConf.EtcdRaft = orderer.EtcdRaft{
		Consenters: []orderer.Consenter{
			{
				Address: orderer.EtcdAddress{
					Host: "host1",
					Port: 123,
				},
				ClientTLSCert: &x509.Certificate{},
				ServerTLSCert: &x509.Certificate{},
			},
		},
		Options: orderer.EtcdRaftOptions{},
	}

	c := New(config)

	err = c.Orderer().SetConfiguration(updatedOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedConfigJSON := fmt.Sprintf(`
{
	"channel_group": {
		"groups": {
			"Orderer": {
				"groups": {
					"OrdererOrg": {
						"groups": {},
						"mod_policy": "Admins",
						"policies": {
							"Admins": {
								"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Admins"
											}
									},
								"version": "0"
							},
							"Endorsement": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "MAJORITY",
										"sub_policy": "Endorsement"
									}
								},
								"version": "0"
							},
							"Readers": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "ANY",
										"sub_policy": "Readers"
									}
								},
								"version": "0"
							},
							"Writers": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "ANY",
										"sub_policy": "Writers"
									}
								},
								"version": "0"
							}
						},
						"values": {
							"Endpoints": {
								"mod_policy": "Admins",
								"value": {
									"addresses": [
									"localhost:123"
								]
								},
								"version": "0"
							},
							"MSP": {
								"mod_policy": "Admins",
								"value": {
									"config": {
										"admins": [
											"%[1]s"
										],
										"crypto_config": {
											"identity_identifier_hash_function": "SHA256",
											"signature_hash_family": "SHA3"
										},
										"fabric_node_ous": {
											"admin_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"client_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"enable": false,
											"orderer_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"peer_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											}
										},
										"intermediate_certs": [
											"%[1]s"
										],
										"name": "MSPID",
										"organizational_unit_identifiers": [
											{
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											}
										],
										"revocation_list": [
											"%[2]s"
										],
										"root_certs": [
											"%[1]s"
										],
										"signing_identity": null,
										"tls_intermediate_certs": [
											"%[1]s"
										],
										"tls_root_certs": [
											"%[1]s"
										]
									},
									"type": 0
								},
								"version": "0"
							}
						},
						"version": "0"
					}
				},
				"mod_policy": "Admins",
				"policies": {
					"Admins": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
							}
						},
						"version": "0"
					},
					"BlockValidation": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
							}
						},
						"version": "0"
					},
					"Readers": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
							}
						},
						"version": "0"
					},
					"Writers": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
							}
						},
						"version": "0"
					}
				},
				"values": {
					"BatchSize": {
						"mod_policy": "Admins",
						"value": {
							"absolute_max_bytes": 100,
							"max_message_count": 10000,
							"preferred_max_bytes": 100
						},
						"version": "0"
					},
					"BatchTimeout": {
						"mod_policy": "Admins",
						"value": {
							"timeout": "0s"
						},
						"version": "0"
					},
					"Capabilities": {
						"mod_policy": "Admins",
						"value": {
							"capabilities": {
							"V1_3": {}
							}
						},
						"version": "0"
					},
					"ChannelRestrictions": {
						"mod_policy": "Admins",
						"value": {
							"max_count": "0"
						},
						"version": "0"
					},
					"ConsensusType": {
						"mod_policy": "Admins",
						"value": {
							"metadata": {
							"consenters": [
							{
							"client_tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
							"host": "host1",
							"port": 123,
							"server_tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
							}
							],
							"options": {
							"election_tick": 0,
							"heartbeat_tick": 0,
							"max_inflight_blocks": 0,
							"snapshot_interval_size": 0,
							"tick_interval": ""
							}
							},
							"state": "STATE_NORMAL",
							"type": "etcdraft"
						},
						"version": "0"
					}
				},
				"version": "0"
			}
		},
		"mod_policy": "",
		"policies": {
			"Admins": {
				"mod_policy": "Admins",
				"policy": {
					"type": 3,
					"value": {
						"rule": "MAJORITY",
						"sub_policy": "Admins"
					}
				},
				"version": "0"
			}
		},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
`, certBase64, crlBase64)

	buf := &bytes.Buffer{}
	err = protolator.DeepMarshalJSON(buf, c.updated)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func TestOrdererConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ordererType string
	}{
		{
			ordererType: orderer.ConsensusTypeSolo,
		},
		{
			ordererType: orderer.ConsensusTypeKafka,
		},
		{
			ordererType: orderer.ConsensusTypeEtcdRaft,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.ordererType, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseOrdererConf, _ := baseOrdererOfType(t, tt.ordererType)

			ordererGroup, err := newOrdererGroup(baseOrdererConf)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						OrdererGroupKey: ordererGroup,
					},
					Values: map[string]*cb.ConfigValue{},
				},
			}

			c := New(config)

			ordererConf, err := c.Orderer().Configuration()
			gt.Expect(err).NotTo(HaveOccurred())
			gt.Expect(ordererConf).To(Equal(baseOrdererConf))
		})
	}
}

func TestOrdererConfigurationNoOrdererEndpoints(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseOrdererOfType(t, orderer.ConsensusTypeSolo)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
			Values: map[string]*cb.ConfigValue{},
		},
	}

	delete(config.ChannelGroup.Groups[OrdererGroupKey].Groups["OrdererOrg"].Values, EndpointsKey)

	c := New(config)

	ordererConf, err := c.Orderer().Configuration()
	gt.Expect(err).NotTo(HaveOccurred())
	baseOrdererConf.Organizations[0].OrdererEndpoints = nil
	gt.Expect(ordererConf).To(Equal(baseOrdererConf))
}

func TestOrdererConfigurationFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		ordererType string
		configMod   func(*cb.Config, *GomegaWithT)
		expectedErr string
	}{
		{
			testName:    "When the config contains an unknown consensus type",
			ordererType: orderer.ConsensusTypeSolo,
			configMod: func(config *cb.Config, gt *GomegaWithT) {
				err := setValue(config.ChannelGroup.Groups[OrdererGroupKey], consensusTypeValue("badtype", nil, 0), AdminsPolicyKey)
				gt.Expect(err).NotTo(HaveOccurred())
			},
			expectedErr: "config contains unknown consensus type 'badtype'",
		},
		{
			testName:    "Missing Kafka brokers for kafka orderer",
			ordererType: orderer.ConsensusTypeKafka,
			configMod: func(config *cb.Config, gt *GomegaWithT) {
				delete(config.ChannelGroup.Groups[OrdererGroupKey].Values, orderer.KafkaBrokersKey)
			},
			expectedErr: "unable to find kafka brokers for kafka orderer",
		},
		{
			testName:    "Failed unmarshaling etcd raft metadata",
			ordererType: orderer.ConsensusTypeEtcdRaft,
			configMod: func(config *cb.Config, gt *GomegaWithT) {
				err := setValue(config.ChannelGroup.Groups[OrdererGroupKey], consensusTypeValue(orderer.ConsensusTypeEtcdRaft, nil, 0), AdminsPolicyKey)
				gt.Expect(err).NotTo(HaveOccurred())
			},
			expectedErr: "unmarshaling etcd raft metadata: missing etcdraft metadata options in config",
		},
		{
			testName:    "Invalid batch timeout",
			ordererType: orderer.ConsensusTypeSolo,
			configMod: func(config *cb.Config, gt *GomegaWithT) {
				err := setValue(config.ChannelGroup.Groups[OrdererGroupKey], batchTimeoutValue("invalidtime"), AdminsPolicyKey)
				gt.Expect(err).NotTo(HaveOccurred())
			},
			expectedErr: "batch timeout configuration 'invalidtime' is not a duration string",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseOrdererConfig, _ := baseOrdererOfType(t, tt.ordererType)
			ordererGroup, err := newOrdererGroup(baseOrdererConfig)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						OrdererGroupKey: ordererGroup,
					},
					Values: map[string]*cb.ConfigValue{},
				},
			}

			if tt.configMod != nil {
				tt.configMod(config, gt)
			}

			c := New(config)

			_, err = c.Orderer().Configuration()
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestSetOrdererOrg(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	orderer, _ := baseSoloOrderer(t)
	ordererGroup, err := newOrdererGroup(orderer)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	msp, _ := baseMSP(t)
	org := Organization{
		Name:     "OrdererOrg2",
		Policies: orgStandardPolicies(),
		OrdererEndpoints: []string{
			"localhost:123",
		},
		MSP: msp,
	}
	certBase64, crlBase64 := certCRLBase64(t, org.MSP)

	expectedConfigJSON := fmt.Sprintf(`
{
	"groups": {},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"Endorsement": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Endorsement"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"Endpoints": {
			"mod_policy": "Admins",
			"value": {
				"addresses": [
					"localhost:123"
				]
			},
			"version": "0"
		},
		"MSP": {
			"mod_policy": "Admins",
			"value": {
				"config": {
					"admins": [
						"%[1]s"
					],
					"crypto_config": {
						"identity_identifier_hash_function": "SHA256",
						"signature_hash_family": "SHA3"
					},
					"fabric_node_ous": {
						"admin_ou_identifier": {
							"certificate": "%[1]s",
							"organizational_unit_identifier": "OUID"
						},
						"client_ou_identifier": {
							"certificate": "%[1]s",
							"organizational_unit_identifier": "OUID"
						},
						"enable": false,
						"orderer_ou_identifier": {
							"certificate": "%[1]s",
							"organizational_unit_identifier": "OUID"
						},
						"peer_ou_identifier": {
							"certificate": "%[1]s",
							"organizational_unit_identifier": "OUID"
						}
					},
					"intermediate_certs": [
						"%[1]s"
					],
					"name": "MSPID",
					"organizational_unit_identifiers": [
						{
							"certificate": "%[1]s",
							"organizational_unit_identifier": "OUID"
						}
					],
					"revocation_list": [
						"%[2]s"
					],
					"root_certs": [
						"%[1]s"
					],
					"signing_identity": null,
					"tls_intermediate_certs": [
						"%[1]s"
					],
					"tls_root_certs": [
						"%[1]s"
					]
				},
				"type": 0
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, certBase64, crlBase64)

	err = c.Orderer().SetOrganization(org)
	gt.Expect(err).NotTo(HaveOccurred())

	actualOrdererConfigGroup := c.Orderer().Organization("OrdererOrg2").orgGroup
	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &ordererext.DynamicOrdererOrgGroup{ConfigGroup: actualOrdererConfigGroup})
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func TestSetOrdererOrgFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	orderer, _ := baseSoloOrderer(t)
	ordererGroup, err := newOrdererGroup(orderer)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	org := Organization{
		Name: "OrdererOrg2",
	}

	err = c.Orderer().SetOrganization(org)
	gt.Expect(err).To(MatchError("failed to create orderer org OrdererOrg2: no policies defined"))
}

func TestSetOrdererEndpoint(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: {
					Version: 0,
					Groups: map[string]*cb.ConfigGroup{
						"Orderer1Org": {
							Groups: map[string]*cb.ConfigGroup{},
							Values: map[string]*cb.ConfigValue{
								EndpointsKey: {
									ModPolicy: AdminsPolicyKey,
									Value: marshalOrPanic(&cb.OrdererAddresses{
										Addresses: []string{"127.0.0.1:8050"},
									}),
								},
							},
							Policies: map[string]*cb.ConfigPolicy{},
						},
					},
					Values:   map[string]*cb.ConfigValue{},
					Policies: map[string]*cb.ConfigPolicy{},
				},
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
		Sequence: 0,
	}

	c := New(config)

	expectedUpdatedConfigJSON := `
{
	"channel_group": {
		"groups": {
			"Orderer": {
				"groups": {
                    "Orderer1Org": {
						"groups": {},
						"mod_policy": "",
						"policies": {},
						"values": {
							"Endpoints": {
								"mod_policy": "Admins",
								"value": {
									"addresses": [
										"127.0.0.1:8050",
										"127.0.0.1:9050"
									]
								},
								"version": "0"
							}
						},
						"version": "0"
					}
				},
                "mod_policy": "",
		        "policies": {},
		        "values": {},
				"version": "0"
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
	`
	expectedUpdatedConfig := &cb.Config{}
	err := protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedUpdatedConfigJSON), expectedUpdatedConfig)
	gt.Expect(err).ToNot(HaveOccurred())

	newOrderer1OrgEndpoint := Address{Host: "127.0.0.1", Port: 9050}
	err = c.Orderer().Organization("Orderer1Org").SetEndpoint(newOrderer1OrgEndpoint)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedUpdatedConfig)).To(BeTrue())
}

func TestRemoveOrdererEndpoint(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: {
					Version: 0,
					Groups: map[string]*cb.ConfigGroup{
						"OrdererOrg": {
							Groups: map[string]*cb.ConfigGroup{},
							Values: map[string]*cb.ConfigValue{
								EndpointsKey: {
									ModPolicy: AdminsPolicyKey,
									Value: marshalOrPanic(&cb.OrdererAddresses{
										Addresses: []string{"127.0.0.1:7050",
											"127.0.0.1:8050"},
									}),
								},
							},
							Policies: map[string]*cb.ConfigPolicy{},
						},
					},
					Values:   map[string]*cb.ConfigValue{},
					Policies: map[string]*cb.ConfigPolicy{},
				},
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
		Sequence: 0,
	}

	c := New(config)

	expectedUpdatedConfigJSON := `
{
	"channel_group": {
		"groups": {
			"Orderer": {
				"groups": {
					"OrdererOrg": {
						"groups": {},
						"mod_policy": "",
						"policies": {},
						"values": {
							"Endpoints": {
								"mod_policy": "Admins",
								"value": {
									"addresses": [
										"127.0.0.1:7050"
									]
								},
								"version": "0"
							}
						},
						"version": "0"
					}
				},
				"mod_policy": "",
				"policies": {},
				"values": {},
				"version": "0"
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
`

	expectedUpdatedConfig := &cb.Config{}
	err := protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedUpdatedConfigJSON), expectedUpdatedConfig)
	gt.Expect(err).ToNot(HaveOccurred())

	removedEndpoint := Address{Host: "127.0.0.1", Port: 8050}
	err = c.Orderer().Organization("OrdererOrg").RemoveEndpoint(removedEndpoint)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedUpdatedConfig)).To(BeTrue())
}

func TestRemoveOrdererEndpointFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: {
					Version: 0,
					Groups: map[string]*cb.ConfigGroup{
						"OrdererOrg": {
							Groups: map[string]*cb.ConfigGroup{},
							Values: map[string]*cb.ConfigValue{
								EndpointsKey: {
									ModPolicy: AdminsPolicyKey,
									Value:     []byte("fire time"),
								},
							},
							Policies: map[string]*cb.ConfigPolicy{},
						},
					},
					Values:   map[string]*cb.ConfigValue{},
					Policies: map[string]*cb.ConfigPolicy{},
				},
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
		Sequence: 0,
	}

	c := New(config)

	err := c.Orderer().Organization("OrdererOrg").RemoveEndpoint(Address{Host: "127.0.0.1", Port: 8050})
	gt.Expect(err).To(MatchError("failed unmarshaling endpoints for orderer org OrdererOrg: proto: can't skip unknown wire type 6"))
}

func TestGetOrdererOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	ordererChannelGroup, _, err := baseOrdererChannelGroup(t, orderer.ConsensusTypeSolo)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: ordererChannelGroup,
	}

	ordererOrgGroup := getOrdererOrg(config, "OrdererOrg")
	gt.Expect(ordererOrgGroup).To(Equal(config.ChannelGroup.Groups[OrdererGroupKey].Groups["OrdererOrg"]))
}

func TestOrdererCapabilities(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	ordererCapabilities, err := c.Orderer().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(ordererCapabilities).To(Equal(baseOrdererConf.Capabilities))

	// Delete the capabilities key and assert retrieval to return nil
	delete(c.Orderer().ordererGroup.Values, CapabilitiesKey)
	ordererCapabilities, err = c.Orderer().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(ordererCapabilities).To(BeNil())
}

func TestAddOrdererCapability(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	ordererOrgMSP := baseOrdererConf.Organizations[0].MSP
	orgCertBase64, orgCRLBase64 := certCRLBase64(t, ordererOrgMSP)

	expectedConfigGroupJSON := fmt.Sprintf(`{
	"groups": {
		"OrdererOrg": {
			"groups": {},
			"mod_policy": "Admins",
			"policies": {
				"Admins": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
						}
					},
					"version": "0"
				},
				"Endorsement": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Endorsement"
						}
					},
					"version": "0"
				},
				"Readers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
						}
					},
					"version": "0"
				},
				"Writers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
						}
					},
					"version": "0"
				}
			},
			"values": {
				"Endpoints": {
					"mod_policy": "Admins",
					"value": {
						"addresses": [
							"localhost:123"
						]
					},
					"version": "0"
				},
				"MSP": {
					"mod_policy": "Admins",
					"value": {
						"config": {
							"admins": [
								"%[1]s"
							],
							"crypto_config": {
								"identity_identifier_hash_function": "SHA256",
								"signature_hash_family": "SHA3"
							},
							"fabric_node_ous": {
								"admin_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"client_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"enable": false,
								"orderer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"peer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							},
							"intermediate_certs": [
								"%[1]s"
							],
							"name": "MSPID",
							"organizational_unit_identifiers": [
								{
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							],
							"revocation_list": [
								"%[2]s"
							],
							"root_certs": [
								"%[1]s"
							],
							"signing_identity": null,
							"tls_intermediate_certs": [
								"%[1]s"
							],
							"tls_root_certs": [
								"%[1]s"
							]
						},
						"type": 0
					},
					"version": "0"
				}
			},
			"version": "0"
		}
	},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"BlockValidation": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"BatchSize": {
			"mod_policy": "Admins",
			"value": {
				"absolute_max_bytes": 100,
				"max_message_count": 100,
				"preferred_max_bytes": 100
			},
			"version": "0"
		},
		"BatchTimeout": {
			"mod_policy": "Admins",
			"value": {
				"timeout": "0s"
			},
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {
					"V1_3": {},
					"V3_0": {}
				}
			},
			"version": "0"
		},
		"ChannelRestrictions": {
			"mod_policy": "Admins",
			"value": null,
			"version": "0"
		},
		"ConsensusType": {
			"mod_policy": "Admins",
			"value": {
				"metadata": null,
				"state": "STATE_NORMAL",
				"type": "solo"
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, orgCertBase64, orgCRLBase64)

	capability := "V3_0"
	err = c.Orderer().AddCapability(capability)
	gt.Expect(err).NotTo(HaveOccurred())

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &ordererext.DynamicOrdererGroup{ConfigGroup: c.Orderer().ordererGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConfigGroupJSON))
}

func TestAddOrdererCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName     string
		capability   string
		ordererGroup func(og *cb.ConfigGroup)
		expectedErr  string
	}{
		{
			testName:   "when retrieving existing capabilities",
			capability: "V1_3",
			ordererGroup: func(og *cb.ConfigGroup) {
				og.Values = map[string]*cb.ConfigValue{
					CapabilitiesKey: {
						Value: []byte("foobar"),
					},
				}
			},
			expectedErr: "retrieving orderer capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseOrdererConf, _ := baseSoloOrderer(t)
			ordererGroup, err := newOrdererGroup(baseOrdererConf)
			gt.Expect(err).NotTo(HaveOccurred())
			tt.ordererGroup(ordererGroup)

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						OrdererGroupKey: ordererGroup,
					},
				},
			}

			c := New(config)

			err = c.Orderer().AddCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestRemoveOrdererCapability(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	ordererOrgMSP := baseOrdererConf.Organizations[0].MSP
	orgCertBase64, orgCRLBase64 := certCRLBase64(t, ordererOrgMSP)

	expectedConfigGroupJSON := fmt.Sprintf(`{
	"groups": {
		"OrdererOrg": {
			"groups": {},
			"mod_policy": "Admins",
			"policies": {
				"Admins": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Admins"
						}
					},
					"version": "0"
				},
				"Endorsement": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "MAJORITY",
							"sub_policy": "Endorsement"
						}
					},
					"version": "0"
				},
				"Readers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Readers"
						}
					},
					"version": "0"
				},
				"Writers": {
					"mod_policy": "Admins",
					"policy": {
						"type": 3,
						"value": {
							"rule": "ANY",
							"sub_policy": "Writers"
						}
					},
					"version": "0"
				}
			},
			"values": {
				"Endpoints": {
					"mod_policy": "Admins",
					"value": {
						"addresses": [
							"localhost:123"
						]
					},
					"version": "0"
				},
				"MSP": {
					"mod_policy": "Admins",
					"value": {
						"config": {
							"admins": [
								"%[1]s"
							],
							"crypto_config": {
								"identity_identifier_hash_function": "SHA256",
								"signature_hash_family": "SHA3"
							},
							"fabric_node_ous": {
								"admin_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"client_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"enable": false,
								"orderer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								},
								"peer_ou_identifier": {
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							},
							"intermediate_certs": [
								"%[1]s"
							],
							"name": "MSPID",
							"organizational_unit_identifiers": [
								{
									"certificate": "%[1]s",
									"organizational_unit_identifier": "OUID"
								}
							],
							"revocation_list": [
								"%[2]s"
							],
							"root_certs": [
								"%[1]s"
							],
							"signing_identity": null,
							"tls_intermediate_certs": [
								"%[1]s"
							],
							"tls_root_certs": [
								"%[1]s"
							]
						},
						"type": 0
					},
					"version": "0"
				}
			},
			"version": "0"
		}
	},
	"mod_policy": "Admins",
	"policies": {
		"Admins": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "MAJORITY",
					"sub_policy": "Admins"
				}
			},
			"version": "0"
		},
		"BlockValidation": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		},
		"Readers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Readers"
				}
			},
			"version": "0"
		},
		"Writers": {
			"mod_policy": "Admins",
			"policy": {
				"type": 3,
				"value": {
					"rule": "ANY",
					"sub_policy": "Writers"
				}
			},
			"version": "0"
		}
	},
	"values": {
		"BatchSize": {
			"mod_policy": "Admins",
			"value": {
				"absolute_max_bytes": 100,
				"max_message_count": 100,
				"preferred_max_bytes": 100
			},
			"version": "0"
		},
		"BatchTimeout": {
			"mod_policy": "Admins",
			"value": {
				"timeout": "0s"
			},
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {}
			},
			"version": "0"
		},
		"ChannelRestrictions": {
			"mod_policy": "Admins",
			"value": null,
			"version": "0"
		},
		"ConsensusType": {
			"mod_policy": "Admins",
			"value": {
				"metadata": null,
				"state": "STATE_NORMAL",
				"type": "solo"
			},
			"version": "0"
		}
	},
	"version": "0"
}
`, orgCertBase64, orgCRLBase64)

	capability := "V1_3"
	err = c.Orderer().RemoveCapability(capability)
	gt.Expect(err).NotTo(HaveOccurred())

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &ordererext.DynamicOrdererGroup{ConfigGroup: c.Orderer().ordererGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConfigGroupJSON))
}

func TestRemoveOrdererCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName     string
		capability   string
		ordererGroup func(og *cb.ConfigGroup)
		expectedErr  string
	}{
		{
			testName:   "when capability does not exist",
			capability: "V3_0",
			ordererGroup: func(og *cb.ConfigGroup) {
			},
			expectedErr: "capability not set",
		},
		{
			testName:   "when retrieving existing capabilities",
			capability: "V3_0",
			ordererGroup: func(og *cb.ConfigGroup) {
				og.Values = map[string]*cb.ConfigValue{
					CapabilitiesKey: {
						Value: []byte("foobar"),
					},
				}
			},
			expectedErr: "retrieving orderer capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseOrdererConf, _ := baseSoloOrderer(t)
			ordererGroup, err := newOrdererGroup(baseOrdererConf)
			gt.Expect(err).NotTo(HaveOccurred())
			tt.ordererGroup(ordererGroup)

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						OrdererGroupKey: ordererGroup,
					},
				},
			}

			c := New(config)

			err = c.Orderer().RemoveCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestOrdererOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, _ := baseSystemChannelProfile(t)
	channelGroup, err := newSystemChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	expectedOrg := channel.Orderer.Organizations[0]

	tests := []struct {
		name        string
		orgName     string
		expectedErr string
	}{
		{
			name:        "success",
			orgName:     "OrdererOrg",
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			org, err := c.Orderer().Organization(tc.orgName).Configuration()
			if tc.expectedErr != "" {
				gt.Expect(err).To(MatchError(tc.expectedErr))
				gt.Expect(Organization{}).To(Equal(org))
			} else {
				gt.Expect(err).NotTo(HaveOccurred())
				gt.Expect(expectedOrg).To(Equal(org))
			}
		})
	}
}

func TestRemoveOrdererOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, _ := baseSystemChannelProfile(t)
	channelGroup, err := newSystemChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	c.Orderer().RemoveOrganization("OrdererOrg")
	gt.Expect(c.Orderer().Organization("OrdererOrg")).To(BeNil())
}

func TestSetOrdererPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	expectedPolicies := map[string]Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		BlockValidationPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		"TestPolicy": {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Endorsement",
		},
	}

	err = c.Orderer().SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "ANY Endorsement"})
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := c.Orderer().Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestSetOrdererPolicyFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	err = c.Orderer().SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{})
	gt.Expect(err).To(MatchError("failed to set policy 'TestPolicy': unknown policy type: "))
}

func TestRemoveOrdererPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	baseOrdererConf.Policies["TestPolicy"] = baseOrdererConf.Policies[AdminsPolicyKey]

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	expectedPolicies := map[string]Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		BlockValidationPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
	}

	err = c.Orderer().RemovePolicy("TestPolicy")
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := c.Orderer().Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestRemoveOrdererPolicyFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	baseOrdererConf.Policies["TestPolicy"] = baseOrdererConf.Policies[AdminsPolicyKey]

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	tests := []struct {
		testName      string
		ordererGrpMod func(cb.ConfigGroup) *cb.ConfigGroup
		policyName    string
		expectedErr   string
	}{
		{
			testName: "when removing blockvalidation policy",
			ordererGrpMod: func(og cb.ConfigGroup) *cb.ConfigGroup {
				return &og
			},
			policyName:  BlockValidationPolicyKey,
			expectedErr: "BlockValidation policy must be defined",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			gt := NewGomegaWithT(t)

			ordererGroup := tt.ordererGrpMod(*ordererGroup)
			if ordererGroup == nil {
				delete(config.ChannelGroup.Groups, OrdererGroupKey)
			} else {
				config.ChannelGroup.Groups[OrdererGroupKey] = ordererGroup
			}

			err = c.Orderer().RemovePolicy(tt.policyName)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestSetOrdererOrgPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	expectedPolicies := map[string]Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		EndorsementPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
		"TestPolicy": {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Endorsement",
		},
	}

	ordererOrg := c.Orderer().Organization("OrdererOrg")
	err = ordererOrg.SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "ANY Endorsement"})
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := ordererOrg.Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestSetOrdererOrgPolicyFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	err = c.Orderer().Organization("OrdererOrg").SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{})
	gt.Expect(err).To(MatchError("unknown policy type: "))
}

func TestRemoveOrdererOrgPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseOrdererConf, _ := baseSoloOrderer(t)
	baseOrdererConf.Organizations[0].Policies["TestPolicy"] = baseOrdererConf.Organizations[0].Policies[AdminsPolicyKey]

	ordererGroup, err := newOrdererGroup(baseOrdererConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Orderer": ordererGroup,
			},
		},
	}

	c := New(config)

	expectedPolicies := map[string]Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		EndorsementPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
	}

	err = c.Orderer().Organization("OrdererOrg").RemovePolicy("TestPolicy")
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := c.Orderer().Organization("OrdererOrg").Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestOrdererMSP(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	soloOrderer, _ := baseSoloOrderer(t)
	expectedMSP := soloOrderer.Organizations[0].MSP

	ordererGroup, err := newOrdererGroup(soloOrderer)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				OrdererGroupKey: ordererGroup,
			},
		},
	}

	c := New(config)

	msp, err := c.Orderer().Organization("OrdererOrg").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(msp).To(Equal(expectedMSP))
}

func TestUpdateOrdererMSP(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, privKeys, err := baseOrdererChannelGroup(t, orderer.ConsensusTypeSolo)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}
	c := New(config)

	ordererMSP, err := c.Orderer().Organization("OrdererOrg").MSP()
	gt.Expect(err).NotTo(HaveOccurred())

	ordererCertBase64, ordererCRLBase64 := certCRLBase64(t, ordererMSP)

	newRootCert, newRootPrivKey := generateCACertAndPrivateKey(t, "anotherca-org1.example.com")
	newRootCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newRootCert))
	ordererMSP.RootCerts = append(ordererMSP.RootCerts, newRootCert)

	newIntermediateCert, _ := generateIntermediateCACertAndPrivateKey(t, "anotherca-org1.example.com", newRootCert, newRootPrivKey)
	newIntermediateCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newIntermediateCert))
	ordererMSP.IntermediateCerts = append(ordererMSP.IntermediateCerts, newIntermediateCert)

	cert := ordererMSP.RootCerts[0]
	certToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, "org1.example.com", cert, privKeys[0])
	signingIdentity := &SigningIdentity{
		Certificate: cert,
		PrivateKey:  privKeys[0],
		MSPID:       "MSPID",
	}
	newCRL, err := c.Orderer().Organization("OrdererOrg").CreateMSPCRL(signingIdentity, certToRevoke)
	gt.Expect(err).NotTo(HaveOccurred())
	pemNewCRL, err := pemEncodeCRL(newCRL)
	gt.Expect(err).NotTo(HaveOccurred())
	newCRLBase64 := base64.StdEncoding.EncodeToString(pemNewCRL)
	ordererMSP.RevocationList = append(ordererMSP.RevocationList, newCRL)

	err = c.Orderer().Organization("OrdererOrg").SetMSP(ordererMSP)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedConfigJSON := fmt.Sprintf(`
{
	"channel_group": {
		"groups": {
			"Orderer": {
				"groups": {
					"OrdererOrg": {
						"groups": {},
						"mod_policy": "Admins",
						"policies": {
							"Admins": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "MAJORITY",
										"sub_policy": "Admins"
									}
								},
								"version": "0"
							},
							"Endorsement": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "MAJORITY",
										"sub_policy": "Endorsement"
									}
								},
								"version": "0"
							},
							"Readers": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "ANY",
										"sub_policy": "Readers"
									}
								},
								"version": "0"
							},
							"Writers": {
								"mod_policy": "Admins",
								"policy": {
									"type": 3,
									"value": {
										"rule": "ANY",
										"sub_policy": "Writers"
									}
								},
								"version": "0"
							}
						},
						"values": {
							"Endpoints": {
								"mod_policy": "Admins",
								"value": {
									"addresses": [
										"localhost:123"
									]
								},
								"version": "0"
							},
							"MSP": {
								"mod_policy": "Admins",
								"value": {
									"config": {
										"admins": [
											"%[1]s"
										],
										"crypto_config": {
											"identity_identifier_hash_function": "SHA256",
											"signature_hash_family": "SHA3"
										},
										"fabric_node_ous": {
											"admin_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"client_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"enable": false,
											"orderer_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											},
											"peer_ou_identifier": {
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											}
										},
										"intermediate_certs": [
											"%[1]s",
											"%[2]s"
										],
										"name": "MSPID",
										"organizational_unit_identifiers": [
											{
												"certificate": "%[1]s",
												"organizational_unit_identifier": "OUID"
											}
										],
										"revocation_list": [
											"%[3]s",
											"%[4]s"
										],
										"root_certs": [
											"%[1]s",
											"%[5]s"
										],
										"signing_identity": null,
										"tls_intermediate_certs": [
											"%[1]s"
										],
										"tls_root_certs": [
											"%[1]s"
										]
									},
									"type": 0
								},
								"version": "0"
							}
						},
						"version": "0"
					}
				},
				"mod_policy": "Admins",
				"policies": {
					"Admins": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
								"rule": "MAJORITY",
								"sub_policy": "Admins"
							}
						},
						"version": "0"
					},
					"BlockValidation": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
								"rule": "ANY",
								"sub_policy": "Writers"
							}
						},
						"version": "0"
					},
					"Readers": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
								"rule": "ANY",
								"sub_policy": "Readers"
							}
						},
						"version": "0"
					},
					"Writers": {
						"mod_policy": "Admins",
						"policy": {
							"type": 3,
							"value": {
								"rule": "ANY",
								"sub_policy": "Writers"
							}
						},
						"version": "0"
					}
				},
				"values": {
					"BatchSize": {
						"mod_policy": "Admins",
						"value": {
							"absolute_max_bytes": 100,
							"max_message_count": 100,
							"preferred_max_bytes": 100
						},
						"version": "0"
					},
					"BatchTimeout": {
						"mod_policy": "Admins",
						"value": {
							"timeout": "0s"
						},
						"version": "0"
					},
					"Capabilities": {
						"mod_policy": "Admins",
						"value": {
							"capabilities": {
								"V1_3": {}
							}
						},
						"version": "0"
					},
					"ChannelRestrictions": {
						"mod_policy": "Admins",
						"value": null,
						"version": "0"
					},
					"ConsensusType": {
						"mod_policy": "Admins",
						"value": {
							"metadata": null,
							"state": "STATE_NORMAL",
							"type": "solo"
						},
						"version": "0"
					}
				},
				"version": "0"
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}`, ordererCertBase64, newIntermediateCertBase64, ordererCRLBase64, newCRLBase64, newRootCertBase64)

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, c.updated)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func TestUpdateOrdererMSPFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec        string
		mspMod      func(MSP) MSP
		orgName     string
		expectedErr string
	}{
		{
			spec: "updating msp name",
			mspMod: func(msp MSP) MSP {
				msp.Name = "thiscantbegood"
				return msp
			},
			orgName:     "OrdererOrg",
			expectedErr: "MSP name cannot be changed",
		},
		{
			spec: "invalid root ca cert keyusage",
			mspMod: func(msp MSP) MSP {
				msp.RootCerts = []*x509.Certificate{
					{
						SerialNumber: big.NewInt(7),
						KeyUsage:     x509.KeyUsageKeyAgreement,
					},
				}
				return msp
			},
			orgName:     "OrdererOrg",
			expectedErr: "invalid root cert: KeyUsage must be x509.KeyUsageCertSign. serial number: 7",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			channelGroup, _, err := baseOrdererChannelGroup(t, orderer.ConsensusTypeSolo)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: channelGroup,
			}
			c := New(config)

			ordererMSP, err := c.Orderer().Organization("OrdererOrg").MSP()
			gt.Expect(err).NotTo(HaveOccurred())

			ordererMSP = tc.mspMod(ordererMSP)
			err = c.Orderer().Organization(tc.orgName).SetMSP(ordererMSP)
			gt.Expect(err).To(MatchError(tc.expectedErr))
		})
	}
}

func baseOrdererOfType(t *testing.T, ordererType string) (Orderer, []*ecdsa.PrivateKey) {
	switch ordererType {
	case orderer.ConsensusTypeKafka:
		return baseKafkaOrderer(t)
	case orderer.ConsensusTypeEtcdRaft:
		return baseEtcdRaftOrderer(t)
	default:
		return baseSoloOrderer(t)
	}
}

func baseSoloOrderer(t *testing.T) (Orderer, []*ecdsa.PrivateKey) {
	baseMSP, privKey := baseMSP(t)
	return Orderer{
		Policies:    ordererStandardPolicies(),
		OrdererType: orderer.ConsensusTypeSolo,
		Organizations: []Organization{
			{
				Name:     "OrdererOrg",
				Policies: orgStandardPolicies(),
				OrdererEndpoints: []string{
					"localhost:123",
				},
				MSP: baseMSP,
			},
		},
		Capabilities: []string{"V1_3"},
		BatchSize: orderer.BatchSize{
			MaxMessageCount:   100,
			AbsoluteMaxBytes:  100,
			PreferredMaxBytes: 100,
		},
		State: orderer.ConsensusStateNormal,
	}, []*ecdsa.PrivateKey{privKey}
}

func baseKafkaOrderer(t *testing.T) (Orderer, []*ecdsa.PrivateKey) {
	soloOrderer, privKeys := baseSoloOrderer(t)
	soloOrderer.OrdererType = orderer.ConsensusTypeKafka
	soloOrderer.Kafka = orderer.Kafka{
		Brokers: []string{"broker1", "broker2"},
	}

	return soloOrderer, privKeys
}

func baseEtcdRaftOrderer(t *testing.T) (Orderer, []*ecdsa.PrivateKey) {
	caCert, caPrivKey := generateCACertAndPrivateKey(t, "orderer-org")
	cert, _ := generateCertAndPrivateKeyFromCACert(t, "orderer-org", caCert, caPrivKey)

	soloOrderer, privKeys := baseSoloOrderer(t)
	soloOrderer.OrdererType = orderer.ConsensusTypeEtcdRaft
	soloOrderer.EtcdRaft = orderer.EtcdRaft{
		Consenters: []orderer.Consenter{
			{
				Address: orderer.EtcdAddress{
					Host: "node-1.example.com",
					Port: 7050,
				},
				ClientTLSCert: cert,
				ServerTLSCert: cert,
			},
			{
				Address: orderer.EtcdAddress{
					Host: "node-2.example.com",
					Port: 7050,
				},
				ClientTLSCert: cert,
				ServerTLSCert: cert,
			},
			{
				Address: orderer.EtcdAddress{
					Host: "node-3.example.com",
					Port: 7050,
				},
				ClientTLSCert: cert,
				ServerTLSCert: cert,
			},
		},
		Options: orderer.EtcdRaftOptions{},
	}

	return soloOrderer, privKeys
}

// baseOrdererChannelGroup creates a channel config group
// that only contains an Orderer group.
func baseOrdererChannelGroup(t *testing.T, ordererType string) (*cb.ConfigGroup, []*ecdsa.PrivateKey, error) {
	channelGroup := newConfigGroup()

	ordererConf, privKeys := baseOrdererOfType(t, ordererType)
	ordererGroup, err := newOrdererGroup(ordererConf)
	if err != nil {
		return nil, nil, err
	}
	channelGroup.Groups[OrdererGroupKey] = ordererGroup

	return channelGroup, privKeys, nil
}

// marshalOrPanic is a helper for proto marshal.
func marshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}

	return data
}
