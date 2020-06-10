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
	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/commonext"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestNewConsortiumsGroup(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	org1CertBase64, org1CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[1].MSP)

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
}
`, org1CertBase64, org1CRLBase64, org2CertBase64, org2CRLBase64)

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &commonext.DynamicConsortiumsGroup{ConfigGroup: consortiumsGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConsortiumsGroup))
}

func TestNewConsortiumsGroupFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)
	consortiums[0].Organizations[0].Policies = nil

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).To(MatchError("org group 'Org1': no policies defined"))
	gt.Expect(consortiumsGroup).To(BeNil())
}

func TestSetConsortiumOrg(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)
	org1CertBase64, org1CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[1].MSP)

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

	msp, _ := baseMSP(t)
	orgToAdd := Organization{
		Name:     "Org3",
		Policies: orgStandardPolicies(),
		MSP:      msp,
	}
	org3CertBase64, org3CRLBase64 := certCRLBase64(t, orgToAdd.MSP)

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
`, org1CertBase64, org1CRLBase64, org2CertBase64, org2CRLBase64, org3CertBase64, org3CRLBase64)

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfigJSON), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	err = c.Consortium("Consortium1").SetOrganization(orgToAdd)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedConfigProto)).To(BeTrue())
}

func TestSetConsortiumOrgFailures(t *testing.T) {
	t.Parallel()

	orgToAdd := Organization{
		Name: "test-org",
	}

	for _, test := range []struct {
		name        string
		org         Organization
		consortium  string
		config      *cb.Config
		expectedErr string
	}{
		{
			name:        "When the organization doesn't have policies defined",
			org:         orgToAdd,
			consortium:  "",
			expectedErr: "failed to create consortium org test-org: no policies defined",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			consortiums, _ := baseConsortiums(t)

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

			err = c.Consortium(test.consortium).SetOrganization(test.org)
			gt.Expect(err).To(MatchError(test.expectedErr))
		})
	}
}

func TestRemoveConsortium(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)
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

	c.Consortiums().RemoveConsortium("Consortium1")

	gt.Expect(c.Consortium("Consortium1")).To(BeNil())
}

func TestGetConsortiums(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	baseConsortiums, _ := baseConsortiums(t)
	baseOrderer, _ := baseSoloOrderer(t)
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

	consortiums, err := c.Consortiums().Configuration()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(len(baseConsortiums)).To(Equal(len(consortiums)))
}

func TestGetConsortiumOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	consortiumGroup, _, err := baseConsortiumChannelGroup(t)
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

	consortiums, _ := baseConsortiums(t)
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

	err = c.Consortiums().SetConsortium(newConsortium)
	gt.Expect(err).NotTo(HaveOccurred())

	org1CertBase64, org1CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[0].MSP)
	org2CertBase64, org2CRLBase64 := certCRLBase64(t, consortiums[0].Organizations[1].MSP)

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
`, org1CertBase64, org1CRLBase64, org2CertBase64, org2CRLBase64)

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfigJSON), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedConfigProto)).To(BeTrue())
}

func TestConsortiumOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, _ := baseSystemChannelProfile(t)
	channelGroup, err := newSystemChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	expectedOrg := channel.Consortiums[0].Organizations[0]

	tests := []struct {
		name           string
		consortiumName string
		orgName        string
		expectedErr    string
	}{
		{
			name:           "success",
			consortiumName: "Consortium1",
			orgName:        "Org1",
			expectedErr:    "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			org, err := c.Consortium(tc.consortiumName).Organization(tc.orgName).Configuration()
			if tc.expectedErr != "" {
				gt.Expect(Organization{}).To(Equal(org))
				gt.Expect(err).To(MatchError(tc.expectedErr))
			} else {
				gt.Expect(err).ToNot(HaveOccurred())
				gt.Expect(expectedOrg).To(Equal(org))
			}
		})
	}
}

func TestRemoveConsortiumOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, _ := baseSystemChannelProfile(t)
	channelGroup, err := newSystemChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	c.Consortium("Consortium1").RemoveOrganization("Org1")
	gt.Expect(c.Consortium("Consortium1").Organization("Org1")).To(BeNil())
}

func TestSetConsortiumOrgPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
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
			Rule: "MAJORITY Endorsement",
		},
	}

	consortium1Org1 := c.Consortium("Consortium1").Organization("Org1")
	err = consortium1Org1.SetPolicy("TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "MAJORITY Endorsement"})
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := consortium1Org1.Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestSetConsortiumOrgPolicyFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
			},
		},
	}

	c := New(config)

	for _, test := range []struct {
		name        string
		consortium  string
		org         string
		policy      Policy
		expectedErr string
	}{
		{
			name:        "When setting empty policy fails",
			consortium:  "Consortium1",
			org:         "Org1",
			policy:      Policy{},
			expectedErr: "failed to set policy 'TestPolicy' to consortium org 'Org1': unknown policy type: ",
		},
	} {
		err := c.Consortium(test.consortium).Organization(test.org).SetPolicy("TestPolicy", test.policy)
		gt.Expect(err).To(MatchError(test.expectedErr))
	}
}

func TestRemoveConsortiumOrgPolicy(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)

	consortiums[0].Organizations[0].Policies["TestPolicy"] = Policy{Type: ImplicitMetaPolicyType, Rule: "MAJORITY Endorsement"}

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
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

	consortium1Org1 := c.Consortium("Consortium1").Organization("Org1")
	consortium1Org1.RemovePolicy("TestPolicy")

	updatedPolicies, err := consortium1Org1.Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestConsortiumOrgPolicies(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
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

	policies, err := c.Consortium("Consortium1").Organization("Org1").Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(policies).To(Equal(expectedPolicies))
}

func TestConsortiumMSP(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	consortiums, _ := baseConsortiums(t)
	expectedMSP := consortiums[0].Organizations[0].MSP

	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ConsortiumsGroupKey: consortiumsGroup,
			},
		},
	}

	c := New(config)

	msp, err := c.Consortium("Consortium1").Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(msp).To(Equal(expectedMSP))
}

func TestSetConsortiumMSP(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	consortiumGroup, privKeys, err := baseConsortiumChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: consortiumGroup,
	}
	c := New(config)

	consortium1 := c.Consortium("Consortium1")
	consortiumOrg1MSP, err := consortium1.Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	consortiumOrg2MSP, err := consortium1.Organization("Org2").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	consortiumOrg1CertBase64, consortiumOrg1CRLBase64 := certCRLBase64(t, consortiumOrg1MSP)
	consortiumOrg2CertBase64, consortiumOrg2CRLBase64 := certCRLBase64(t, consortiumOrg2MSP)

	newRootCert, newRootPrivKey := generateCACertAndPrivateKey(t, "anotherca-org1.example.com")
	newRootCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newRootCert))
	consortiumOrg1MSP.RootCerts = append(consortiumOrg1MSP.RootCerts, newRootCert)

	newIntermediateCert, _ := generateIntermediateCACertAndPrivateKey(t, "anotherca-org1.example.com", newRootCert, newRootPrivKey)
	newIntermediateCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newIntermediateCert))
	consortiumOrg1MSP.IntermediateCerts = append(consortiumOrg1MSP.IntermediateCerts, newIntermediateCert)

	cert := consortiumOrg1MSP.RootCerts[0]
	privKey := privKeys[0]
	certToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, "org1.example.com", cert, privKey)
	signingIdentity := &SigningIdentity{
		Certificate: cert,
		PrivateKey:  privKey,
		MSPID:       "MSPID",
	}
	newCRL, err := consortium1.Organization("Org1").CreateMSPCRL(signingIdentity, certToRevoke)
	gt.Expect(err).NotTo(HaveOccurred())
	pemNewCRL, err := pemEncodeCRL(newCRL)
	gt.Expect(err).NotTo(HaveOccurred())
	newCRLBase64 := base64.StdEncoding.EncodeToString(pemNewCRL)
	consortiumOrg1MSP.RevocationList = append(consortiumOrg1MSP.RevocationList, newCRL)

	err = consortium1.Organization("Org1").SetMSP(consortiumOrg1MSP)
	gt.Expect(err).NotTo(HaveOccurred())

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
													"%[6]s"
												],
												"crypto_config": {
													"identity_identifier_hash_function": "SHA256",
													"signature_hash_family": "SHA3"
												},
												"fabric_node_ous": {
													"admin_ou_identifier": {
														"certificate": "%[6]s",
														"organizational_unit_identifier": "OUID"
													},
													"client_ou_identifier": {
														"certificate": "%[6]s",
														"organizational_unit_identifier": "OUID"
													},
													"enable": false,
													"orderer_ou_identifier": {
														"certificate": "%[6]s",
														"organizational_unit_identifier": "OUID"
													},
													"peer_ou_identifier": {
														"certificate": "%[6]s",
														"organizational_unit_identifier": "OUID"
													}
												},
												"intermediate_certs": [
													"%[6]s"
												],
												"name": "MSPID",
												"organizational_unit_identifiers": [
													{
														"certificate": "%[6]s",
														"organizational_unit_identifier": "OUID"
													}
												],
												"revocation_list": [
													"%[7]s"
												],
												"root_certs": [
													"%[6]s"
												],
												"signing_identity": null,
												"tls_intermediate_certs": [
													"%[6]s"
												],
												"tls_root_certs": [
													"%[6]s"
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
`, consortiumOrg1CertBase64, newIntermediateCertBase64, consortiumOrg1CRLBase64, newCRLBase64, newRootCertBase64, consortiumOrg2CertBase64, consortiumOrg2CRLBase64)

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, c.updated)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func TestSetConsortiumMSPFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec           string
		mspMod         func(MSP) MSP
		consortiumName string
		orgName        string
		expectedErr    string
	}{
		{
			spec: "updating msp name",
			mspMod: func(msp MSP) MSP {
				msp.Name = "thiscantbegood"
				return msp
			},
			consortiumName: "Consortium1",
			orgName:        "Org1",
			expectedErr:    "MSP name cannot be changed",
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
			consortiumName: "Consortium1",
			orgName:        "Org1",
			expectedErr:    "invalid root cert: KeyUsage must be x509.KeyUsageCertSign. serial number: 7",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			consortiumGroup, _, err := baseConsortiumChannelGroup(t)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: consortiumGroup,
			}
			c := New(config)

			consortiumOrg1 := c.Consortium("Consortium1").Organization("Org1")
			consortiumOrg1MSP, err := consortiumOrg1.MSP()
			gt.Expect(err).NotTo(HaveOccurred())

			consortiumOrg1MSP = tc.mspMod(consortiumOrg1MSP)
			err = consortiumOrg1.SetMSP(consortiumOrg1MSP)
			gt.Expect(err).To(MatchError(tc.expectedErr))
		})
	}
}

func baseConsortiums(t *testing.T) ([]Consortium, []*ecdsa.PrivateKey) {
	org1MSP, org1PrivKey := baseMSP(t)
	org2MSP, org2PrivKey := baseMSP(t)

	return []Consortium{
		{
			Name: "Consortium1",
			Organizations: []Organization{
				{
					Name:     "Org1",
					Policies: orgStandardPolicies(),
					MSP:      org1MSP,
				},
				{
					Name:     "Org2",
					Policies: orgStandardPolicies(),
					MSP:      org2MSP,
				},
			},
		},
	}, []*ecdsa.PrivateKey{org1PrivKey, org2PrivKey}
}

func baseConsortiumChannelGroup(t *testing.T) (*cb.ConfigGroup, []*ecdsa.PrivateKey, error) {
	channelGroup := newConfigGroup()

	consortiums, privKeys := baseConsortiums(t)
	consortiumsGroup, err := newConsortiumsGroup(consortiums)
	if err != nil {
		return nil, nil, err
	}

	channelGroup.Groups[ConsortiumsGroupKey] = consortiumsGroup

	return channelGroup, privKeys, nil
}
