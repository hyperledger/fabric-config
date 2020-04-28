/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/commonext"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestNewConsortiumsGroup(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	org1CertBase64, org1PKBase64, org1CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2PKBase64, org2CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[1].MSP)

	expectedConsortiumsGroup := fmt.Sprintf(`{
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
									"signing_identity": {
										"private_signer": {
											"key_identifier": "SKI-1",
											"key_material": "%[3]s"
										},
										"public_signer": "%[1]s"
									},
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
										"%[4]s"
									],
									"crypto_config": {
										"identity_identifier_hash_function": "SHA256",
										"signature_hash_family": "SHA3"
									},
									"fabric_node_ous": {
										"admin_ou_identifier": {
											"certificate": "%[4]s",
											"organizational_unit_identifier": "OUID"
										},
										"client_ou_identifier": {
											"certificate": "%[4]s",
											"organizational_unit_identifier": "OUID"
										},
										"enable": false,
										"orderer_ou_identifier": {
											"certificate": "%[4]s",
											"organizational_unit_identifier": "OUID"
										},
										"peer_ou_identifier": {
											"certificate": "%[4]s",
											"organizational_unit_identifier": "OUID"
										}
									},
									"intermediate_certs": [
										"%[4]s"
									],
									"name": "MSPID",
									"organizational_unit_identifiers": [
										{
											"certificate": "%[4]s",
											"organizational_unit_identifier": "OUID"
										}
									],
									"revocation_list": [
										"%[5]s"
									],
									"root_certs": [
										"%[4]s"
									],
									"signing_identity": {
										"private_signer": {
											"key_identifier": "SKI-1",
											"key_material": "%[6]s"
										},
										"public_signer": "%[4]s"
									},
									"tls_intermediate_certs": [
										"%[4]s"
									],
									"tls_root_certs": [
										"%[4]s"
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
}
`, org1CertBase64, org1CRLBase64, org1PKBase64, org2CertBase64, org2CRLBase64, org2PKBase64)

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &commonext.DynamicConsortiumsGroup{ConfigGroup: consortiumsGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConsortiumsGroup))
}

func TestNewConsortiumsGroupFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	consortiums[0].Organizations[0].Policies = nil

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).To(MatchError("org group 'Org1': no policies defined"))
	gt.Expect(consortiumsGroup).To(BeNil())
}

func TestSetConsortiumOrg(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	org1CertBase64, org1PKBase64, org1CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2PKBase64, org2CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[1].MSP)

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Consortiums": consortiumsGroup,
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
	}

	c := New(config)

	orgToAdd := Organization{
		Name:     "Org3",
		Policies: orgStandardPolicies(),
		MSP:      baseMSP(t),
	}
	org3CertBase64, org3PKBase64, org3CRLBase64 := certPrivKeyCRLBase64(t, orgToAdd.MSP)

	expectedConfigJSON := fmt.Sprintf(`
{
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
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[3]s"
													},
													"public_signer": "%[1]s"
												},
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
													"%[4]s"
												],
												"crypto_config": {
													"identity_identifier_hash_function": "SHA256",
													"signature_hash_family": "SHA3"
												},
												"fabric_node_ous": {
													"admin_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"client_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"enable": false,
													"orderer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"peer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												},
												"intermediate_certs": [
													"%[4]s"
												],
												"name": "MSPID",
												"organizational_unit_identifiers": [
													{
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												],
												"revocation_list": [
													"%[5]s"
												],
												"root_certs": [
													"%[4]s"
												],
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[6]s"
													},
													"public_signer": "%[4]s"
												},
												"tls_intermediate_certs": [
													"%[4]s"
												],
												"tls_root_certs": [
													"%[4]s"
												]
											},
											"type": 0
										},
										"version": "0"
									}
								},
								"version": "0"
							},
							"Org3": {
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
													"%[7]s"
												],
												"crypto_config": {
													"identity_identifier_hash_function": "SHA256",
													"signature_hash_family": "SHA3"
												},
												"fabric_node_ous": {
													"admin_ou_identifier": {
														"certificate": "%[7]s",
														"organizational_unit_identifier": "OUID"
													},
													"client_ou_identifier": {
														"certificate": "%[7]s",
														"organizational_unit_identifier": "OUID"
													},
													"enable": false,
													"orderer_ou_identifier": {
														"certificate": "%[7]s",
														"organizational_unit_identifier": "OUID"
													},
													"peer_ou_identifier": {
														"certificate": "%[7]s",
														"organizational_unit_identifier": "OUID"
													}
												},
												"intermediate_certs": [
													"%[7]s"
												],
												"name": "MSPID",
												"organizational_unit_identifiers": [
													{
														"certificate": "%[7]s",
														"organizational_unit_identifier": "OUID"
													}
												],
												"revocation_list": [
													"%[8]s"
												],
												"root_certs": [
													"%[7]s"
												],
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[9]s"
													},
													"public_signer": "%[7]s"
												},
												"tls_intermediate_certs": [
													"%[7]s"
												],
												"tls_root_certs": [
													"%[7]s"
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
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
`, org1CertBase64, org1CRLBase64, org1PKBase64, org2CertBase64, org2CRLBase64, org2PKBase64, org3CertBase64, org3CRLBase64, org3PKBase64)

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfigJSON), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	err = c.SetConsortiumOrg(orgToAdd, "Consortium1")
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.UpdatedConfig(), expectedConfigProto)).To(BeTrue())
}

func TestSetConsortiumOrgFailures(t *testing.T) {
	t.Parallel()

	orgToAdd := Organization{
		Name:     "test-org",
		Policies: orgStandardPolicies(),
	}

	for _, test := range []struct {
		name        string
		org         Organization
		consortium  string
		config      *cb.Config
		expectedErr string
	}{
		{
			name:        "When the consortium name is not specified",
			org:         orgToAdd,
			consortium:  "",
			expectedErr: "consortium is required",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			consortiums := baseConsortiums(t)

			consortiumsGroup, err := newConsortiumsGroup(consortiums)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						"Consortiums": consortiumsGroup,
					},
				},
			}

			c := New(config)

			err = c.SetConsortiumOrg(test.org, test.consortium)
			gt.Expect(err).To(MatchError(test.expectedErr))
		})
	}
}

func TestRemoveConsortium(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
	}

	c := New(config)

	c.RemoveConsortium("Consortium1")

	updatedConsortiumsGroup := c.UpdatedConfig().ChannelGroup.Groups[ConsortiumsGroupKey]
	gt.Expect(updatedConsortiumsGroup.Groups["Consortium1"]).To(BeNil())
}

func TestGetConsortiums(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	baseConsortiums := baseConsortiums(t)
	baseOrderer := baseSoloOrderer(t)
	policies := standardPolicies()

	channel := Channel{
		Consortiums:  baseConsortiums,
		Orderer:      baseOrderer,
		Capabilities: []string{"V2_0"},
		Policies:     policies,
		Consortium:   "testconsortium",
	}
	channelGroup, err := newSystemChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{ChannelGroup: channelGroup}
	c := New(config)

	consortiums, err := c.Consortiums()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(len(baseConsortiums)).To(Equal(len(consortiums)))
}

func TestGetConsortiumOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	consortiumGroup, err := baseConsortiumChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: consortiumGroup,
	}

	org1ConfigGroup := getConsortiumOrg(config, "Consortium1", "Org1")
	gt.Expect(org1ConfigGroup).To(Equal(config.ChannelGroup.Groups[ConsortiumsGroupKey].Groups["Consortium1"].Groups["Org1"]))
}

func TestSetConsortium(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Consortiums": consortiumsGroup,
			},
		},
	}

	c := New(config)

	newConsortium := consortiums[0]
	newConsortium.Name = "Consortium2"

	err = c.SetConsortium(newConsortium)
	gt.Expect(err).NotTo(HaveOccurred())

	org1CertBase64, org1PKBase64, org1CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2PKBase64, org2CRLBase64 := certPrivKeyCRLBase64(t, consortiums[0].Organizations[1].MSP)

	expectedConfigJSON := fmt.Sprintf(`
{
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
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[3]s"
													},
													"public_signer": "%[1]s"
												},
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
													"%[4]s"
												],
												"crypto_config": {
													"identity_identifier_hash_function": "SHA256",
													"signature_hash_family": "SHA3"
												},
												"fabric_node_ous": {
													"admin_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"client_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"enable": false,
													"orderer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"peer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												},
												"intermediate_certs": [
													"%[4]s"
												],
												"name": "MSPID",
												"organizational_unit_identifiers": [
													{
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												],
												"revocation_list": [
													"%[5]s"
												],
												"root_certs": [
													"%[4]s"
												],
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[6]s"
													},
													"public_signer": "%[4]s"
												},
												"tls_intermediate_certs": [
													"%[4]s"
												],
												"tls_root_certs": [
													"%[4]s"
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
					},
					"Consortium2": {
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
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[3]s"
													},
													"public_signer": "%[1]s"
												},
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
													"%[4]s"
												],
												"crypto_config": {
													"identity_identifier_hash_function": "SHA256",
													"signature_hash_family": "SHA3"
												},
												"fabric_node_ous": {
													"admin_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"client_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"enable": false,
													"orderer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													},
													"peer_ou_identifier": {
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												},
												"intermediate_certs": [
													"%[4]s"
												],
												"name": "MSPID",
												"organizational_unit_identifiers": [
													{
														"certificate": "%[4]s",
														"organizational_unit_identifier": "OUID"
													}
												],
												"revocation_list": [
													"%[5]s"
												],
												"root_certs": [
													"%[4]s"
												],
												"signing_identity": {
													"private_signer": {
														"key_identifier": "SKI-1",
														"key_material": "%[6]s"
													},
													"public_signer": "%[4]s"
												},
												"tls_intermediate_certs": [
													"%[4]s"
												],
												"tls_root_certs": [
													"%[4]s"
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
						"mod_policy": "",
						"policies": {},
						"values": {},
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
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
`, org1CertBase64, org1CRLBase64, org1PKBase64, org2CertBase64, org2CRLBase64, org2PKBase64)

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfigJSON), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.UpdatedConfig(), expectedConfigProto)).To(BeTrue())
}

func TestSetConsortiumFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Consortiums": consortiumsGroup,
			},
		},
	}

	c := New(config)

	newConsortium := consortiums[0]
	newConsortium.Name = ""

	err = c.SetConsortium(newConsortium)
	gt.Expect(err).To(MatchError("consortium is required"))
}

func baseConsortiums(t *testing.T) []Consortium {
	return []Consortium{
		{
			Name: "Consortium1",
			Organizations: []Organization{
				{
					Name:     "Org1",
					Policies: orgStandardPolicies(),
					MSP:      baseMSP(t),
				},
				{
					Name:     "Org2",
					Policies: orgStandardPolicies(),
					MSP:      baseMSP(t),
				},
			},
		},
	}
}

func baseConsortiumChannelGroup(t *testing.T) (*cb.ConfigGroup, error) {
	channelGroup := newConfigGroup()

	consortiums := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	if err != nil {
		return nil, err
	}

	channelGroup.Groups[ConsortiumsGroupKey] = consortiumsGroup

	return channelGroup, nil
}
