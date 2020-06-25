/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/protolator"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestNewConfigTx(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	channel, _, err := baseApplicationChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	original := &cb.Config{
		ChannelGroup: channel,
	}

	c := New(original)
	gt.Expect(proto.Equal(c.OriginalConfig(), original)).To(BeTrue())
	gt.Expect(proto.Equal(c.UpdatedConfig(), original)).To(BeTrue())

	err = c.Application().AddCapability("fake-capability")
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.OriginalConfig(), original)).To(BeTrue())
	gt.Expect(proto.Equal(c.UpdatedConfig(), original)).To(BeFalse())
}

func TestNewCreateChannelTx(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	// The TwoOrgsChannel profile is defined in standard_networks.go under the BasicSolo configuration
	// configtxgen -profile TwoOrgsChannel -channelID testChannel
	expectedEnvelopeJSON := `{
		"payload": {
			"data": {
				"config_update": {
					"channel_id": "testchannel",
					"isolated_data": {},
					"read_set": {
						"groups": {
							"Application": {
								"groups": {
									"Org1": {
										"groups": {},
										"mod_policy": "",
										"policies": {},
										"values": {},
										"version": "0"
									},
									"Org2": {
										"groups": {},
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
							}
						},
						"mod_policy": "",
						"policies": {},
						"values": {
							"Consortium": {
								"mod_policy": "",
								"value": null,
								"version": "0"
							}
						},
						"version": "0"
					},
					"write_set": {
						"groups": {
							"Application": {
								"groups": {
									"Org1": {
										"groups": {},
										"mod_policy": "",
										"policies": {},
										"values": {},
										"version": "0"
									},
									"Org2": {
										"groups": {},
										"mod_policy": "",
										"policies": {},
										"values": {},
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
									"Capabilities": {
										"mod_policy": "Admins",
										"value": {
											"capabilities": {
												"V1_3": {}
											}
										},
										"version": "0"
									},
									"ACLs": {
										"mod_policy": "Admins",
										"value": {
											"acls": {
												"acl1": {
													"policy_ref": "hi"
												}
											}
										},
										"version": "0"
									}
								},
								"version": "1"
							}
						},
						"mod_policy": "",
						"policies": {},
						"values": {
							"Consortium": {
								"mod_policy": "",
								"value": {
									"name": "SampleConsortium"
								},
								"version": "0"
							}
						},
						"version": "0"
					}
				},
				"signatures": []
			},
			"header": {
				"channel_header": {
					"channel_id": "testchannel",
					"epoch": "0",
					"extension": null,
					"timestamp": "2020-02-17T15:49:56Z",
					"tls_cert_hash": null,
					"tx_id": "",
					"type": 2,
					"version": 0
				},
				"signature_header": null
			}
		},
		"signature": null
	}`

	profile := baseProfile(t)

	// creating a create channel transaction
	marshaledCreateChannelTx, err := NewMarshaledCreateChannelTx(profile, "testchannel")
	gt.Expect(err).NotTo(HaveOccurred())
	envelope, err := NewEnvelope(marshaledCreateChannelTx)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(envelope).ToNot(BeNil())

	// Unmarshaling actual and expected envelope to set
	// the expected timestamp to the actual timestamp
	expectedEnvelope := cb.Envelope{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedEnvelopeJSON), &expectedEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedPayload := cb.Payload{}
	err = proto.Unmarshal(expectedEnvelope.Payload, &expectedPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedHeader := cb.ChannelHeader{}
	err = proto.Unmarshal(expectedPayload.Header.ChannelHeader, &expectedHeader)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedData := cb.ConfigUpdateEnvelope{}
	err = proto.Unmarshal(expectedPayload.Data, &expectedData)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedConfigUpdate := cb.ConfigUpdate{}
	err = proto.Unmarshal(expectedData.ConfigUpdate, &expectedConfigUpdate)
	gt.Expect(err).NotTo(HaveOccurred())

	actualPayload := cb.Payload{}
	err = proto.Unmarshal(envelope.Payload, &actualPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	actualHeader := cb.ChannelHeader{}
	err = proto.Unmarshal(actualPayload.Header.ChannelHeader, &actualHeader)
	gt.Expect(err).NotTo(HaveOccurred())

	actualData := cb.ConfigUpdateEnvelope{}
	err = proto.Unmarshal(actualPayload.Data, &actualData)
	gt.Expect(err).NotTo(HaveOccurred())

	actualConfigUpdate := cb.ConfigUpdate{}
	err = proto.Unmarshal(actualData.ConfigUpdate, &actualConfigUpdate)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(actualConfigUpdate).To(Equal(expectedConfigUpdate))

	// setting timestamps to match in ConfigUpdate
	actualTimestamp := actualHeader.Timestamp

	expectedHeader.Timestamp = actualTimestamp

	expectedData.ConfigUpdate = actualData.ConfigUpdate

	// Remarshaling envelopes with updated timestamps
	expectedPayload.Data, err = proto.Marshal(&expectedData)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedPayload.Header.ChannelHeader, err = proto.Marshal(&expectedHeader)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedEnvelope.Payload, err = proto.Marshal(&expectedPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(envelope).To(Equal(&expectedEnvelope))
}

func TestNewCreateChannelTxFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName   string
		profileMod func() Channel
		channelID  string
		err        error
	}{
		{
			testName: "When creating the default config template with no Admins policies defined fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				delete(profile.Application.Policies, AdminsPolicyKey)
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"no Admins policy defined"),
		},
		{
			testName: "When creating the default config template with no Readers policies defined fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				delete(profile.Application.Policies, ReadersPolicyKey)
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"no Readers policy defined"),
		},
		{
			testName: "When creating the default config template with no Writers policies defined fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				delete(profile.Application.Policies, WritersPolicyKey)
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"no Writers policy defined"),
		},
		{
			testName: "When creating the default config template with an invalid ImplicitMetaPolicy rule fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ALL",
					Type: ImplicitMetaPolicyType,
				}
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"invalid implicit meta policy rule: 'ALL': expected two space separated " +
				"tokens, but got 1"),
		},
		{
			testName: "When creating the default config template with an invalid ImplicitMetaPolicy rule fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ANYY Readers",
					Type: ImplicitMetaPolicyType,
				}
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"invalid implicit meta policy rule: 'ANYY Readers': unknown rule type " +
				"'ANYY', expected ALL, ANY, or MAJORITY"),
		},
		{
			testName: "When creating the default config template with SignatureTypePolicy and bad rule fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ANYY Readers",
					Type: SignaturePolicyType,
				}
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"invalid signature policy rule: 'ANYY Readers': Cannot transition " +
				"token types from VARIABLE [ANYY] to VARIABLE [Readers]"),
		},
		{
			testName: "When creating the default config template with an unknown policy type fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ALL",
					Type: "GreenPolicy",
				}
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: failed to create application group: " +
				"unknown policy type: GreenPolicy"),
		},
		{
			testName: "When creating the default config template without consortium",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Consortium = ""
				return profile
			},
			channelID: "testchannel",
			err:       errors.New("creating default config template: consortium is not defined in channel config"),
		},
		{
			testName: "When channel ID is not specified in config",
			profileMod: func() Channel {
				profile := baseProfile(t)
				return profile
			},
			channelID: "",
			err:       errors.New("profile's channel ID is required"),
		},
		{
			testName: "When creating the application group fails",
			profileMod: func() Channel {
				profile := baseProfile(t)
				profile.Application.Policies = nil
				return profile
			},
			channelID: "testchannel",
			err: errors.New("creating default config template: " +
				"failed to create application group: no policies defined"),
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			profile := tt.profileMod()

			marshaledCreateChannelTx, err := NewMarshaledCreateChannelTx(profile, tt.channelID)
			gt.Expect(marshaledCreateChannelTx).To(BeNil())
			gt.Expect(err).To(MatchError(tt.err))
		})
	}
}

func TestNewSystemChannelGenesisBlock(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	profile, _, _ := baseSystemChannelProfile(t)

	block, err := NewSystemChannelGenesisBlock(profile, "testsystemchannel")
	gt.Expect(err).ToNot(HaveOccurred())
	gt.Expect(block).ToNot(BeNil())
	gt.Expect(block.Header.Number).To(Equal(uint64(0)))

	org1CertBase64, org1CrlBase64 := certCRLBase64(t, profile.Consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2CrlBase64 := certCRLBase64(t, profile.Consortiums[0].Organizations[1].MSP)
	ordererOrgCertBase64, ordererOrgCrlBase64 := certCRLBase64(t, profile.Orderer.Organizations[0].MSP)

	expectBlockJSON := fmt.Sprintf(`
{
	"data": {
		"data": [
			{
				"payload": {
					"data": {
						"config": {
							"channel_group": {
								"groups": {
									"Consortiums": {
										"groups": {
											"Consortium1": {
												"groups": {
													"Org1": {
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
													},
													"Org2": {
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
															"MSP": {
																"mod_policy": "Admins",
																"value": {
																	"config": {
																		"admins": [
																			"%[3]s"
																		],
																		"crypto_config": {
																			"identity_identifier_hash_function": "SHA256",
																			"signature_hash_family": "SHA3"
																		},
																		"fabric_node_ous": {
																			"admin_ou_identifier": {
																				"certificate": "%[3]s",
																				"organizational_unit_identifier": "OUID"
																			},
																			"client_ou_identifier": {
																				"certificate": "%[3]s",
																				"organizational_unit_identifier": "OUID"
																			},
																			"enable": false,
																			"orderer_ou_identifier": {
																				"certificate": "%[3]s",
																				"organizational_unit_identifier": "OUID"
																			},
																			"peer_ou_identifier": {
																				"certificate": "%[3]s",
																				"organizational_unit_identifier": "OUID"
																			}
																		},
																		"intermediate_certs": [
																			"%[3]s"
																		],
																		"name": "MSPID",
																		"organizational_unit_identifiers": [
																			{
																				"certificate": "%[3]s",
																				"organizational_unit_identifier": "OUID"
																			}
																		],
																		"revocation_list": [
																			"%[4]s"
																		],
																		"root_certs": [
																			"%[3]s"
																		],
																		"signing_identity": null,
																		"tls_intermediate_certs": [
																			"%[3]s"
																		],
																		"tls_root_certs": [
																			"%[3]s"
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
												"mod_policy": "/Channel/Orderer/Admins",
												"policies": {},
												"values": {
													"ChannelCreationPolicy": {
														"mod_policy": "/Channel/Orderer/Admins",
														"value": {
															"type": 3,
															"value": {
																"rule": "ANY",
																"sub_policy": "Admins"
															}
														},
														"version": "0"
													}
												},
												"version": "0"
											}
										},
										"mod_policy": "/Channel/Orderer/Admins",
										"policies": {
											"Admins": {
												"mod_policy": "/Channel/Orderer/Admins",
												"policy": {
													"type": 1,
													"value": {
														"identities": [],
														"rule": {
															"n_out_of": {
																"n": 0,
																"rules": []
															}
														},
														"version": 0
													}
												},
												"version": "0"
											}
										},
										"values": {},
										"version": "0"
									},
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
																	"%[5]s"
																],
																"crypto_config": {
																	"identity_identifier_hash_function": "SHA256",
																	"signature_hash_family": "SHA3"
																},
																"fabric_node_ous": {
																	"admin_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"client_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"enable": false,
																	"orderer_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"peer_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	}
																},
																"intermediate_certs": [
																	"%[5]s"
																],
																"name": "MSPID",
																"organizational_unit_identifiers": [
																	{
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	}
																],
																"revocation_list": [
																	"%[6]s"
																],
																"root_certs": [
																	"%[5]s"
																],
																"signing_identity": null,
																"tls_intermediate_certs": [
																	"%[5]s"
																],
																"tls_root_certs": [
																	"%[5]s"
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
									"BlockDataHashingStructure": {
										"mod_policy": "Admins",
										"value": {
											 "width": 4294967295
											},
										"version": "0"
									},
									"HashingAlgorithm": {
										"mod_policy": "Admins",
										"value": {
											 "name": "SHA256"
											},
										"version": "0"
									},
									"Capabilities": {
										"mod_policy": "Admins",
										"value": {
											"capabilities": {
												"V2_0": {}
											}
										},
										"version": "0"
									}
								},
								"version": "0"
							},
							"sequence": "0"
						},
						"last_update": null
					},
					"header": {
						"channel_header": {
							"channel_id": "testsystemchannel",
							"epoch": "0",
							"extension": null,
							"timestamp": "2020-04-08T11:59:02Z",
							"tls_cert_hash": null,
							"tx_id": "1b9fd2206484ebbfc960c772c2638f83474b957c7a83f4607e94c44205a5fc9f",
							"type": 1,
							"version": 0
						},
						"signature_header": {
							"creator": null,
							"nonce": "9GHTm16kXuzFu8OwUG+Ds3re67UXVPaz"
						}
					}
				},
				"signature": null
			}
		]
	},
	"header": {
		"data_hash": "zYnpX4Xe0k/Wue2m6lEEJwqMzdApznVVUw7n5SLNWmo=",
		"number": "0",
		"previous_hash": null
	},
	"metadata": {
		"metadata": [
			"CgIKAA==",
			"",
			"",
			"",
			""
		]
	}
}
`, org1CertBase64, org1CrlBase64, org2CertBase64, org2CrlBase64, ordererOrgCertBase64, ordererOrgCrlBase64)

	expectedBlock := &cb.Block{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectBlockJSON), expectedBlock)
	gt.Expect(err).ToNot(HaveOccurred())

	expectedEnvelope := &cb.Envelope{}
	err = proto.Unmarshal(expectedBlock.Data.Data[0], expectedEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedPayload := &cb.Payload{}
	err = proto.Unmarshal(expectedEnvelope.Payload, expectedPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedData := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(expectedPayload.Data, expectedData)
	gt.Expect(err).NotTo(HaveOccurred())

	actualEnvelope := &cb.Envelope{}
	err = proto.Unmarshal(block.Data.Data[0], actualEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())

	actualPayload := &cb.Payload{}
	err = proto.Unmarshal(actualEnvelope.Payload, actualPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	actualData := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(actualPayload.Data, actualData)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(actualData).To(Equal(expectedData))

	expectedChannelHeader := &cb.ChannelHeader{}
	err = proto.Unmarshal(expectedPayload.Header.ChannelHeader, expectedChannelHeader)
	gt.Expect(err).NotTo(HaveOccurred())

	actualChannelHeader := &cb.ChannelHeader{}
	err = proto.Unmarshal(actualPayload.Header.ChannelHeader, actualChannelHeader)
	gt.Expect(err).NotTo(HaveOccurred())
	expectedChannelHeader.Timestamp = actualChannelHeader.Timestamp
	expectedChannelHeader.TxId = actualChannelHeader.TxId

	gt.Expect(actualChannelHeader).To(Equal(expectedChannelHeader))
}

func TestNewSystemChannelGenesisBlockFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName   string
		profileMod func() Channel
		channelID  string
		err        error
	}{
		{
			testName: "When channel ID is not specified in config",
			profileMod: func() Channel {
				profile, _, _ := baseSystemChannelProfile(t)
				return profile
			},
			channelID: "",
			err:       errors.New("system channel ID is required"),
		},
		{
			testName: "When creating the default system config template with empty orderer endpoints",
			profileMod: func() Channel {
				profile, _, _ := baseSystemChannelProfile(t)
				profile.Orderer.Organizations[0].OrdererEndpoints = []string{}
				return profile
			},
			channelID: "testsystemchannel",
			err:       errors.New("creating system channel group: orderer endpoints are not defined for org OrdererOrg"),
		},
		{
			testName: "When creating the default config template with empty capabilities",
			profileMod: func() Channel {
				profile, _, _ := baseSystemChannelProfile(t)
				profile.Capabilities = []string{}
				return profile
			},
			channelID: "testsystemchannel",
			err:       errors.New("creating system channel group: capabilities is not defined in channel config"),
		},
		{
			testName: "When creating the default config template without orderer",
			profileMod: func() Channel {
				profile, _, _ := baseSystemChannelProfile(t)
				profile.Orderer = Orderer{}
				return profile
			},
			channelID: "testsystemchannel",
			err:       errors.New("creating system channel group: no policies defined"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			profile := tt.profileMod()

			block, err := NewSystemChannelGenesisBlock(profile, tt.channelID)
			gt.Expect(block).To(BeNil())
			gt.Expect(err).To(MatchError(tt.err))
		})
	}
}

func TestNewApplicationChannelGenesisBlock(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	profile, _, _ := baseApplicationChannelProfile(t)

	block, err := NewApplicationChannelGenesisBlock(profile, "testapplicationchannel")
	gt.Expect(err).ToNot(HaveOccurred())
	gt.Expect(block).ToNot(BeNil())
	gt.Expect(block.Header.Number).To(Equal(uint64(0)))

	org1CertBase64, org1CrlBase64 := certCRLBase64(t, profile.Application.Organizations[0].MSP)
	org2CertBase64, org2CrlBase64 := certCRLBase64(t, profile.Application.Organizations[1].MSP)
	ordererOrgCertBase64, ordererOrgCrlBase64 := certCRLBase64(t, profile.Orderer.Organizations[0].MSP)

	expectBlockJSON := fmt.Sprintf(`
{
	"data": {
		"data": [
			{
				"payload": {
					"data": {
						"config": {
							"channel_group": {
								"groups": {
									"Application": {
										"groups": {
											"Org1": {
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
													"LifecycleEndorsement": {
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
											},
											"Org2": {
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
													"LifecycleEndorsement": {
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
													"MSP": {
														"mod_policy": "Admins",
														"value": {
															"config": {
																"admins": [
																	"%[3]s"
																],
																"crypto_config": {
																	"identity_identifier_hash_function": "SHA256",
																	"signature_hash_family": "SHA3"
																},
																"fabric_node_ous": {
																	"admin_ou_identifier": {
																		"certificate": "%[3]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"client_ou_identifier": {
																		"certificate": "%[3]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"enable": false,
																	"orderer_ou_identifier": {
																		"certificate": "%[3]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"peer_ou_identifier": {
																		"certificate": "%[3]s",
																		"organizational_unit_identifier": "OUID"
																	}
																},
																"intermediate_certs": [
																	"%[3]s"
																],
																"name": "MSPID",
																"organizational_unit_identifiers": [
																	{
																		"certificate": "%[3]s",
																		"organizational_unit_identifier": "OUID"
																	}
																],
																"revocation_list": [
																	"%[4]s"
																],
																"root_certs": [
																	"%[3]s"
																],
																"signing_identity": null,
																"tls_intermediate_certs": [
																	"%[3]s"
																],
																"tls_root_certs": [
																	"%[3]s"
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
											"ACLs": {
												"mod_policy": "Admins",
												"value": {
													"acls": {
														"acl1": {
															"policy_ref": "hi"
														}
													}
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
											}
										},
										"version": "0"
									},
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
																	"%[5]s"
																],
																"crypto_config": {
																	"identity_identifier_hash_function": "SHA256",
																	"signature_hash_family": "SHA3"
																},
																"fabric_node_ous": {
																	"admin_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"client_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"enable": false,
																	"orderer_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	},
																	"peer_ou_identifier": {
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	}
																},
																"intermediate_certs": [
																	"%[5]s"
																],
																"name": "MSPID",
																"organizational_unit_identifiers": [
																	{
																		"certificate": "%[5]s",
																		"organizational_unit_identifier": "OUID"
																	}
																],
																"revocation_list": [
																	"%[6]s"
																],
																"root_certs": [
																	"%[5]s"
																],
																"signing_identity": null,
																"tls_intermediate_certs": [
																	"%[5]s"
																],
																"tls_root_certs": [
																	"%[5]s"
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
									"BlockDataHashingStructure": {
										"mod_policy": "Admins",
										"value": {
											"width": 4294967295
										},
										"version": "0"
									},
									"Capabilities": {
										"mod_policy": "Admins",
										"value": {
											"capabilities": {
												"V2_0": {}
											}
										},
										"version": "0"
									},
									"HashingAlgorithm": {
										"mod_policy": "Admins",
										"value": {
											"name": "SHA256"
										},
										"version": "0"
									}
								},
								"version": "0"
							},
							"sequence": "0"
						},
						"last_update": null
					},
					"header": {
						"channel_header": {
							"channel_id": "testapplicationchannel",
							"epoch": "0",
							"extension": null,
							"timestamp": "2020-06-25T17:39:55Z",
							"tls_cert_hash": null,
							"tx_id": "93fcf9cd1e2524021f6ea592801a8b15d5262d54b350c7fe8b6b760a062b7390",
							"type": 1,
							"version": 0
						},
						"signature_header": {
							"creator": null,
							"nonce": "yXFTP7Wz7bAtIMpzFB+WaLe45fYIXjl8"
						}
					}
				},
				"signature": null
			}
		]
	},
	"header": {
		"data_hash": "2FX2z5r8jRx6Jt5QKHt6Ch/eU0ay1bZPrncOL1Q7pIE=",
		"number": "0",
		"previous_hash": null
	},
	"metadata": {
		"metadata": [
			"CgIKAA==",
			"",
			"",
			"",
			""
		]
	}
}
`, org1CertBase64, org1CrlBase64, org2CertBase64, org2CrlBase64, ordererOrgCertBase64, ordererOrgCrlBase64)

	expectedBlock := &cb.Block{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectBlockJSON), expectedBlock)
	gt.Expect(err).ToNot(HaveOccurred())

	expectedEnvelope := &cb.Envelope{}
	err = proto.Unmarshal(expectedBlock.Data.Data[0], expectedEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedPayload := &cb.Payload{}
	err = proto.Unmarshal(expectedEnvelope.Payload, expectedPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedData := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(expectedPayload.Data, expectedData)
	gt.Expect(err).NotTo(HaveOccurred())

	actualEnvelope := &cb.Envelope{}
	err = proto.Unmarshal(block.Data.Data[0], actualEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())

	actualPayload := &cb.Payload{}
	err = proto.Unmarshal(actualEnvelope.Payload, actualPayload)
	gt.Expect(err).NotTo(HaveOccurred())

	actualData := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(actualPayload.Data, actualData)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(actualData).To(Equal(expectedData))

	expectedChannelHeader := &cb.ChannelHeader{}
	err = proto.Unmarshal(expectedPayload.Header.ChannelHeader, expectedChannelHeader)
	gt.Expect(err).NotTo(HaveOccurred())

	actualChannelHeader := &cb.ChannelHeader{}
	err = proto.Unmarshal(actualPayload.Header.ChannelHeader, actualChannelHeader)
	gt.Expect(err).NotTo(HaveOccurred())
	expectedChannelHeader.Timestamp = actualChannelHeader.Timestamp
	expectedChannelHeader.TxId = actualChannelHeader.TxId

	gt.Expect(actualChannelHeader).To(Equal(expectedChannelHeader))
}

func TestNewApplicationChannelGenesisBlockFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName   string
		profileMod func() Channel
		channelID  string
		err        error
	}{
		{
			testName: "When channel ID is not specified in config",
			profileMod: func() Channel {
				profile, _, _ := baseApplicationChannelProfile(t)
				return profile
			},
			channelID: "",
			err:       errors.New("application channel ID is required"),
		},
		{
			testName: "When creating the default application config template with empty orderer endpoints",
			profileMod: func() Channel {
				profile, _, _ := baseApplicationChannelProfile(t)
				profile.Orderer.Organizations[0].OrdererEndpoints = []string{}
				return profile
			},
			channelID: "testapplicationchannel",
			err:       errors.New("creating application channel group: orderer endpoints are not defined for org OrdererOrg"),
		},
		{
			testName: "When creating the default config template with empty capabilities",
			profileMod: func() Channel {
				profile, _, _ := baseApplicationChannelProfile(t)
				profile.Capabilities = []string{}
				return profile
			},
			channelID: "testapplicationchannel",
			err:       errors.New("creating application channel group: capabilities is not defined in channel config"),
		},
		{
			testName: "When creating the default config template without application",
			profileMod: func() Channel {
				profile, _, _ := baseApplicationChannelProfile(t)
				profile.Application = Application{}
				return profile
			},
			channelID: "testapplicationchannel",
			err:       errors.New("creating application channel group: no policies defined"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			profile := tt.profileMod()

			block, err := NewApplicationChannelGenesisBlock(profile, tt.channelID)
			gt.Expect(block).To(BeNil())
			gt.Expect(err).To(MatchError(tt.err))
		})
	}
}

func TestNewEnvelopeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec            string
		marshaledUpdate []byte
		expectedErr     string
	}{
		{
			spec:            "when the marshaled config update isn't a config update",
			marshaledUpdate: []byte("not-a-config-update"),
			expectedErr:     "unmarshaling config update: proto: can't skip unknown wire type 6",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			env, err := NewEnvelope(tc.marshaledUpdate)
			gt.Expect(err).To(MatchError(tc.expectedErr))
			gt.Expect(env).To(BeNil())
		})
	}
}

func TestComputeMarshaledUpdate(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	value1Name := "foo"
	value2Name := "bar"
	original := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Version: 7,
			Values: map[string]*cb.ConfigValue{
				value1Name: {
					Version: 3,
					Value:   []byte("value1value"),
				},
				value2Name: {
					Version: 6,
					Value:   []byte("value2value"),
				},
			},
		},
	}
	updated := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Values: map[string]*cb.ConfigValue{
				value1Name: original.ChannelGroup.Values[value1Name],
				value2Name: {
					Value: []byte("updatedValued2Value"),
				},
			},
		},
	}

	c := ConfigTx{
		original: original,
		updated:  updated,
	}

	channelID := "testChannel"

	expectedReadSet := newConfigGroup()
	expectedReadSet.Version = 7

	expectedWriteSet := newConfigGroup()
	expectedWriteSet.Version = 7
	expectedWriteSet.Values = map[string]*cb.ConfigValue{
		value2Name: {
			Version: 7,
			Value:   []byte("updatedValued2Value"),
		},
	}

	expectedConfig := cb.ConfigUpdate{
		ChannelId: channelID,
		ReadSet:   expectedReadSet,
		WriteSet:  expectedWriteSet,
	}

	marshaledUpdate, err := c.ComputeMarshaledUpdate(channelID)
	gt.Expect(err).NotTo(HaveOccurred())
	configUpdate := &cb.ConfigUpdate{}
	err = proto.Unmarshal(marshaledUpdate, configUpdate)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(proto.Equal(configUpdate, &expectedConfig)).To(BeTrue())
}

func TestComputeUpdateFailures(t *testing.T) {
	t.Parallel()

	original := &cb.Config{}
	updated := &cb.Config{}

	c := ConfigTx{
		original: original,
		updated:  updated,
	}

	for _, test := range []struct {
		name        string
		channelID   string
		expectedErr string
	}{
		{
			name:        "When channel ID is not specified",
			channelID:   "",
			expectedErr: "channel ID is required",
		},
		{
			name:        "When failing to compute update",
			channelID:   "testChannel",
			expectedErr: "failed to compute update: no channel group included for original config",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)
			marshaledUpdate, err := c.ComputeMarshaledUpdate(test.channelID)
			gt.Expect(err).To(MatchError(test.expectedErr))
			gt.Expect(marshaledUpdate).To(BeNil())
		})
	}
}

func TestChannelConfiguration(t *testing.T) {
	t.Parallel()

	baseApplication, _ := baseApplication(t)
	baseConsortiums, _ := baseConsortiums(t)
	baseOrderer, _ := baseSoloOrderer(t)
	policies := standardPolicies()

	tests := []struct {
		name            string
		configMod       func(gt *GomegaWithT) *cb.Config
		expectedChannel Channel
	}{
		{
			name: "retrieve application channel",
			configMod: func(gt *GomegaWithT) *cb.Config {
				channelGroup := newConfigGroup()

				applicationGroup, err := newApplicationGroup(baseApplication)
				gt.Expect(err).NotTo(HaveOccurred())
				for _, org := range baseApplication.Organizations {
					orgGroup, err := newOrgConfigGroup(org)
					gt.Expect(err).NotTo(HaveOccurred())
					applicationGroup.Groups[org.Name] = orgGroup
				}
				channelGroup.Groups[ApplicationGroupKey] = applicationGroup
				err = setPolicies(channelGroup, standardPolicies(), AdminsPolicyKey)
				gt.Expect(err).NotTo(HaveOccurred())

				return &cb.Config{
					ChannelGroup: channelGroup,
				}
			},
			expectedChannel: Channel{
				Application: baseApplication,
				Policies:    standardPolicies(),
			},
		},
		{
			name: "retrieve system channel",
			configMod: func(gt *GomegaWithT) *cb.Config {
				channel := Channel{
					Consortiums:  baseConsortiums,
					Orderer:      baseOrderer,
					Capabilities: []string{"V2_0"},
					Policies:     policies,
					Consortium:   "testconsortium",
				}
				channelGroup, err := newSystemChannelGroup(channel)
				gt.Expect(err).NotTo(HaveOccurred())

				return &cb.Config{
					ChannelGroup: channelGroup,
				}
			},
			expectedChannel: Channel{
				Consortiums:  baseConsortiums,
				Orderer:      baseOrderer,
				Capabilities: []string{"V2_0"},
				Policies:     policies,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			config := tt.configMod(gt)
			c := New(config)

			channel, err := c.Channel().Configuration()
			gt.Expect(err).NotTo(HaveOccurred())
			gt.Expect(channel.Consortium).To(Equal(tt.expectedChannel.Consortium))
			gt.Expect(channel.Application.Organizations).To(ContainElements(tt.expectedChannel.Application.Organizations))
			gt.Expect(channel.Application.Capabilities).To(Equal(tt.expectedChannel.Application.Capabilities))
			gt.Expect(channel.Application.Policies).To(Equal(tt.expectedChannel.Application.Policies))
			gt.Expect(channel.Application.ACLs).To(Equal(tt.expectedChannel.Application.ACLs))
			gt.Expect(channel.Orderer).To(Equal(tt.expectedChannel.Orderer))
			gt.Expect(len(channel.Consortiums)).To(Equal(len(tt.expectedChannel.Consortiums)))
			gt.Expect(channel.Capabilities).To(Equal(tt.expectedChannel.Capabilities))
			gt.Expect(channel.Policies).To(Equal(tt.expectedChannel.Policies))
		})
	}
}

func baseProfile(t *testing.T) Channel {
	application, _ := baseApplication(t)
	return Channel{
		Consortium:   "SampleConsortium",
		Application:  application,
		Capabilities: []string{"V2_0"},
	}
}

func baseSystemChannelProfile(t *testing.T) (Channel, []*ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	consortiums, consortiumsPrivKey := baseConsortiums(t)
	orderer, ordererPrivKeys := baseSoloOrderer(t)
	return Channel{
		Consortiums:  consortiums,
		Orderer:      orderer,
		Capabilities: []string{"V2_0"},
		Policies:     standardPolicies(),
	}, consortiumsPrivKey, ordererPrivKeys[0]
}

func baseApplicationChannelProfile(t *testing.T) (Channel, []*ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	application, applicationPrivKey := baseApplication(t)
	orderer, ordererPrivKeys := baseSoloOrderer(t)
	return Channel{
		Application:  application,
		Orderer:      orderer,
		Capabilities: []string{"V2_0"},
		Policies:     standardPolicies(),
	}, applicationPrivKey, ordererPrivKeys[0]
}

func standardPolicies() map[string]Policy {
	return map[string]Policy{
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
	}
}

func orgStandardPolicies() map[string]Policy {
	policies := standardPolicies()

	policies[EndorsementPolicyKey] = Policy{
		Type: ImplicitMetaPolicyType,
		Rule: "MAJORITY Endorsement",
	}

	return policies
}

func applicationOrgStandardPolicies() map[string]Policy {
	policies := orgStandardPolicies()

	policies[LifecycleEndorsementPolicyKey] = Policy{
		Type: ImplicitMetaPolicyType,
		Rule: "MAJORITY Endorsement",
	}

	return policies
}

func ordererStandardPolicies() map[string]Policy {
	policies := standardPolicies()

	policies[BlockValidationPolicyKey] = Policy{
		Type: ImplicitMetaPolicyType,
		Rule: "ANY Writers",
	}

	return policies
}

// baseApplicationChannelGroup creates a channel config group
// that only contains an Application group.
func baseApplicationChannelGroup(t *testing.T) (*cb.ConfigGroup, []*ecdsa.PrivateKey, error) {
	channelGroup := newConfigGroup()

	application, privKeys := baseApplication(t)
	applicationGroup, err := newApplicationGroup(application)
	if err != nil {
		return nil, nil, err
	}

	for _, org := range application.Organizations {
		orgGroup, err := newOrgConfigGroup(org)
		if err != nil {
			return nil, nil, err
		}
		applicationGroup.Groups[org.Name] = orgGroup
	}

	channelGroup.Groups[ApplicationGroupKey] = applicationGroup

	return channelGroup, privKeys, nil
}
