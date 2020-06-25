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
	"github.com/hyperledger/fabric-config/protolator/protoext/peerext"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestNewApplicationGroup(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	application, _ := baseApplication(t)

	expectedApplicationGroup := `
{
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
		"ACLs": {
			"mod_policy": "Admins",
			"value": "CgwKBGFjbDESBAoCaGk=",
			"version": "0"
		},
		"Capabilities": {
			"mod_policy": "Admins",
			"value": "CggKBFYxXzMSAA==",
			"version": "0"
		}
	},
	"version": "0"
}
`

	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedApplication := &cb.ConfigGroup{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedApplicationGroup), expectedApplication)
	gt.Expect(err).ToNot(HaveOccurred())
	gt.Expect(applicationGroup).To(Equal(expectedApplication))
}

func TestNewApplicationGroupFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName       string
		applicationMod func(*Application)
		expectedErr    string
	}{
		{
			testName: "When application group policy is empty",
			applicationMod: func(a *Application) {
				a.Policies = nil
			},
			expectedErr: "no policies defined",
		},
		{
			testName: "When no Admins policies are defined",
			applicationMod: func(application *Application) {
				delete(application.Policies, AdminsPolicyKey)
			},
			expectedErr: "no Admins policy defined",
		},
		{
			testName: "When no Readers policies are defined",
			applicationMod: func(application *Application) {
				delete(application.Policies, ReadersPolicyKey)
			},
			expectedErr: "no Readers policy defined",
		},
		{
			testName: "When no Writers policies are defined",
			applicationMod: func(application *Application) {
				delete(application.Policies, WritersPolicyKey)
			},
			expectedErr: "no Writers policy defined",
		},
		{
			testName: "When ImplicitMetaPolicy rules' subpolicy is missing",
			applicationMod: func(application *Application) {
				application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ALL",
					Type: ImplicitMetaPolicyType,
				}
			},
			expectedErr: "invalid implicit meta policy rule: 'ALL': expected two space separated " +
				"tokens, but got 1",
		},
		{
			testName: "When ImplicitMetaPolicy rule is invalid",
			applicationMod: func(application *Application) {
				application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ANYY Readers",
					Type: ImplicitMetaPolicyType,
				}
			},
			expectedErr: "invalid implicit meta policy rule: 'ANYY Readers': unknown rule type " +
				"'ANYY', expected ALL, ANY, or MAJORITY",
		},
		{
			testName: "When SignatureTypePolicy rule is invalid",
			applicationMod: func(application *Application) {
				application.Policies[ReadersPolicyKey] = Policy{
					Rule: "ANYY Readers",
					Type: SignaturePolicyType,
				}
			},
			expectedErr: "invalid signature policy rule: 'ANYY Readers': Cannot transition " +
				"token types from VARIABLE [ANYY] to VARIABLE [Readers]",
		},
		{
			testName: "When ImplicitMetaPolicy type is unknown policy type",
			applicationMod: func(application *Application) {
				application.Policies[ReadersPolicyKey] = Policy{
					Type: "GreenPolicy",
				}
			},
			expectedErr: "unknown policy type: GreenPolicy",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			application, _ := baseApplication(t)
			tt.applicationMod(&application)

			configGrp, err := newApplicationGroupTemplate(application)
			gt.Expect(err).To(MatchError(tt.expectedErr))
			gt.Expect(configGrp).To(BeNil())
		})
	}
}

func TestAddAnchorPeer(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
	}

	c := New(config)

	newOrg1AnchorPeer := Address{
		Host: "host3",
		Port: 123,
	}

	newOrg2AnchorPeer := Address{
		Host: "host4",
		Port: 123,
	}

	expectedUpdatedConfigJSON := `
{
	"channel_group": {
		"groups": {
			"Application": {
				"groups": {
					"Org1": {
						"groups": {},
						"mod_policy": "",
						"policies": {},
						"values": {
							"AnchorPeers": {
								"mod_policy": "Admins",
								"value": {
									"anchor_peers": [
									{
									"host": "host3",
									"port": 123
									}
									]
								},
								"version": "0"
							}
						},
						"version": "0"
					},
					"Org2": {
						"groups": {},
						"mod_policy": "",
						"policies": {},
						"values": {
							"AnchorPeers": {
								"mod_policy": "Admins",
								"value": {
									"anchor_peers": [
									{
									"host": "host4",
									"port": 123
									}
									]
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

	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedUpdatedConfigJSON), expectedUpdatedConfig)
	gt.Expect(err).ToNot(HaveOccurred())

	err = c.Application().Organization("Org1").AddAnchorPeer(newOrg1AnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	err = c.Application().Organization("Org2").AddAnchorPeer(newOrg2AnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedUpdatedConfig)).To(BeTrue())
}

func TestRemoveAnchorPeer(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Application": applicationGroup,
			},
			Values:   map[string]*cb.ConfigValue{},
			Policies: map[string]*cb.ConfigPolicy{},
		},
	}

	c := New(config)

	expectedUpdatedConfigJSON := `
{
	"channel_group": {
		"groups": {
			"Application": {
				"groups": {
					"Org1": {
						"groups": {},
						"mod_policy": "",
						"policies": {},
						"values": {
							"AnchorPeers": {
								"mod_policy": "Admins",
								"value": {},
								"version": "0"
							}
						},
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

	anchorPeer1 := Address{Host: "host1", Port: 123}
	applicationOrg1 := c.Application().Organization("Org1")
	err = applicationOrg1.AddAnchorPeer(anchorPeer1)
	gt.Expect(err).NotTo(HaveOccurred())
	expectedUpdatedConfig := &cb.Config{}

	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedUpdatedConfigJSON), expectedUpdatedConfig)
	gt.Expect(err).NotTo(HaveOccurred())

	err = applicationOrg1.RemoveAnchorPeer(anchorPeer1)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(c.updated, expectedUpdatedConfig)).To(BeTrue())
}

func TestRemoveAnchorPeerFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName           string
		orgName            string
		anchorPeerToRemove Address
		configValues       map[string]*cb.ConfigValue
		expectedErr        string
	}{
		{
			testName:           "When the unmarshaling existing anchor peer proto fails",
			orgName:            "Org1",
			anchorPeerToRemove: Address{Host: "host1", Port: 123},
			configValues:       map[string]*cb.ConfigValue{AnchorPeersKey: {Value: []byte("a little fire")}},
			expectedErr:        "failed unmarshaling anchor peer endpoints for application org Org1: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseApplicationConf, _ := baseApplication(t)

			applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
			gt.Expect(err).NotTo(HaveOccurred())

			applicationGroup.Groups["Org1"].Values = tt.configValues

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						"Application": applicationGroup,
					},
				},
			}

			c := New(config)

			err = c.Application().Organization(tt.orgName).RemoveAnchorPeer(tt.anchorPeerToRemove)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestAnchorPeers(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()

	application, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	anchorPeers, err := c.Application().Organization("Org1").AnchorPeers()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(anchorPeers).To(BeNil())
	gt.Expect(anchorPeers).To(HaveLen(0))

	expectedAnchorPeer := Address{Host: "host1", Port: 123}
	err = c.Application().Organization("Org1").AddAnchorPeer(expectedAnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	anchorPeers, err = c.Application().Organization("Org1").AnchorPeers()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(anchorPeers).To(HaveLen(1))
	gt.Expect(anchorPeers[0]).To(Equal(expectedAnchorPeer))

	err = c.Application().Organization("Org1").RemoveAnchorPeer(expectedAnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	anchorPeers, err = c.Application().Organization("Org1").AnchorPeers()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(anchorPeers).To(BeNil())
	gt.Expect(anchorPeers).To(HaveLen(0))
}

func TestSetACL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		configMod   func(*cb.Config)
		newACL      map[string]string
		expectedACL map[string]string
		expectedErr string
	}{
		{
			testName: "success",
			newACL:   map[string]string{"acl2": "newACL"},
			expectedACL: map[string]string{
				"acl2": "newACL",
			},
			expectedErr: "",
		},
		{
			testName: "ACL overwrite",
			newACL:   map[string]string{"acl1": "overwrite acl"},
			expectedACL: map[string]string{
				"acl1": "overwrite acl",
			},
			expectedErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			channelGroup := newConfigGroup()
			baseApplication, _ := baseApplication(t)
			applicationGroup, err := newApplicationGroupTemplate(baseApplication)

			channelGroup.Groups[ApplicationGroupKey] = applicationGroup
			config := &cb.Config{
				ChannelGroup: channelGroup,
			}
			if tt.configMod != nil {
				tt.configMod(config)
			}
			c := New(config)

			err = c.Application().SetACLs(tt.newACL)
			if tt.expectedErr != "" {
				gt.Expect(err).To(MatchError(tt.expectedErr))
			} else {
				gt.Expect(err).NotTo(HaveOccurred())
				acls, err := c.Application().ACLs()
				gt.Expect(err).NotTo(HaveOccurred())
				gt.Expect(acls).To(Equal(tt.expectedACL))
			}
		})
	}
}

func TestRemoveACL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		configMod   func(*cb.Config)
		removeACL   []string
		expectedACL map[string]string
		expectedErr string
	}{
		{
			testName:  "success",
			removeACL: []string{"acl1", "acl2"},
			expectedACL: map[string]string{
				"acl3": "acl3Value",
			},
			expectedErr: "",
		},
		{
			testName:  "remove non-existing acls",
			removeACL: []string{"bad-acl1", "bad-acl2"},
			expectedACL: map[string]string{
				"acl1": "hi",
				"acl2": "acl2Value",
				"acl3": "acl3Value",
			},
			expectedErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			channelGroup := newConfigGroup()
			baseApplication, _ := baseApplication(t)
			baseApplication.ACLs["acl2"] = "acl2Value"
			baseApplication.ACLs["acl3"] = "acl3Value"
			applicationGroup, err := newApplicationGroupTemplate(baseApplication)

			channelGroup.Groups[ApplicationGroupKey] = applicationGroup
			config := &cb.Config{
				ChannelGroup: channelGroup,
			}
			if tt.configMod != nil {
				tt.configMod(config)
			}

			c := New(config)

			err = c.Application().RemoveACLs(tt.removeACL)
			if tt.expectedErr != "" {
				gt.Expect(err).To(MatchError(tt.expectedErr))
			} else {
				gt.Expect(err).NotTo(HaveOccurred())
				acls, err := c.Application().ACLs()
				gt.Expect(err).NotTo(HaveOccurred())
				gt.Expect(acls).To(Equal(tt.expectedACL))
			}
		})
	}
}

func TestSetApplicationOrg(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	application, _ := baseApplication(t)
	appGroup, err := newApplicationGroup(application)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Application": appGroup,
			},
		},
	}

	c := New(config)

	baseMSP, _ := baseMSP(t)
	org := Organization{
		Name:     "Org3",
		Policies: applicationOrgStandardPolicies(),
		MSP:      baseMSP,
		AnchorPeers: []Address{
			{
				Host: "127.0.0.1",
				Port: 7051,
			},
		},
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
		"AnchorPeers": {
			"mod_policy": "Admins",
			"value": {
				"anchor_peers": [
					{
						"host": "127.0.0.1",
						"port": 7051
					}
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

	err = c.Application().SetOrganization(org)
	gt.Expect(err).NotTo(HaveOccurred())

	actualApplicationConfigGroup := c.Application().Organization("Org3").orgGroup
	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &peerext.DynamicApplicationOrgGroup{ConfigGroup: actualApplicationConfigGroup})
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func TestSetApplicationOrgFailures(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	application, _ := baseApplication(t)
	appGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				"Application": appGroup,
			},
		},
	}

	c := New(config)

	org := Organization{
		Name: "Org3",
	}

	err = c.Application().SetOrganization(org)
	gt.Expect(err).To(MatchError("failed to create application org Org3: no policies defined"))
}

func TestApplicationConfiguration(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
		},
	}

	c := New(config)

	for _, org := range baseApplicationConf.Organizations {
		err = c.Application().SetOrganization(org)
		gt.Expect(err).NotTo(HaveOccurred())
	}

	applicationConfig, err := c.Application().Configuration()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(applicationConfig.ACLs).To(Equal(baseApplicationConf.ACLs))
	gt.Expect(applicationConfig.Capabilities).To(Equal(baseApplicationConf.Capabilities))
	gt.Expect(applicationConfig.Policies).To(Equal(baseApplicationConf.Policies))
	gt.Expect(applicationConfig.Organizations).To(ContainElements(baseApplicationConf.Organizations))
}

func TestApplicationConfigurationFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		configMod   func(ConfigTx, Application, *GomegaWithT)
		expectedErr string
	}{
		{
			testName: "Retrieving application org failed",
			configMod: func(c ConfigTx, appOrg Application, gt *GomegaWithT) {
				for _, org := range appOrg.Organizations {
					if org.Name == "Org2" {
						err := c.Application().SetOrganization(org)
						gt.Expect(err).NotTo(HaveOccurred())
					}
				}
			},
			expectedErr: "retrieving application org Org1: config does not contain value for MSP",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseApplicationConf, _ := baseApplication(t)
			applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						ApplicationGroupKey: applicationGroup,
					},
				},
			}

			c := New(config)
			if tt.configMod != nil {
				tt.configMod(c, baseApplicationConf, gt)
			}

			c = New(c.updated)

			_, err = c.Application().Configuration()
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestApplicationACLs(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
		},
	}

	c := New(config)

	applicationACLs, err := c.Application().ACLs()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(applicationACLs).To(Equal(baseApplicationConf.ACLs))
}

func TestApplicationACLsFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
		},
	}

	config.ChannelGroup.Groups[ApplicationGroupKey].Values[ACLsKey] = &cb.ConfigValue{
		Value: []byte("another little fire"),
	}

	c := New(config)

	applicationACLs, err := c.Application().ACLs()
	gt.Expect(err).To(MatchError("unmarshaling ACLs: unexpected EOF"))
	gt.Expect(applicationACLs).To(BeNil())
}

func TestApplicationCapabilities(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroupTemplate(baseApplicationConf)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
		},
	}

	c := New(config)

	applicationCapabilities, err := c.Application().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(applicationCapabilities).To(Equal(baseApplicationConf.Capabilities))

	// Delete the capabilities key and assert retrieval to return nil
	delete(c.Application().applicationGroup.Values, CapabilitiesKey)
	applicationCapabilities, err = c.Application().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(applicationCapabilities).To(BeNil())
}

func TestAddApplicationCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName                string
		capability              string
		equalToOriginal         bool
		expectedConfigGroupJSON string
	}{
		{
			testName:        "success -- adding new capability",
			capability:      "new_capability",
			equalToOriginal: false,
			expectedConfigGroupJSON: `{
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
					"V1_3": {},
					"new_capability": {}
				}
			},
			"version": "0"
		}
	},
	"version": "0"
}
`,
		},
		{
			testName:        "success -- when capability already exists",
			capability:      "V1_3",
			equalToOriginal: true,
			expectedConfigGroupJSON: `{
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
}
`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			baseApp, _ := baseApplication(t)
			appGroup, err := newApplicationGroupTemplate(baseApp)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						ApplicationGroupKey: appGroup,
					},
				},
			}

			c := New(config)

			err = c.Application().AddCapability(tt.capability)
			gt.Expect(err).NotTo(HaveOccurred())

			updatedApplicationGroupJSON := bytes.Buffer{}
			err = protolator.DeepMarshalJSON(&updatedApplicationGroupJSON, &peerext.DynamicApplicationGroup{ConfigGroup: c.Application().applicationGroup})
			gt.Expect(err).NotTo(HaveOccurred())
			originalApplicationGroupJSON := bytes.Buffer{}
			err = protolator.DeepMarshalJSON(&originalApplicationGroupJSON, &peerext.DynamicApplicationGroup{ConfigGroup: c.original.ChannelGroup.Groups[ApplicationGroupKey]})
			gt.Expect(err).NotTo(HaveOccurred())

			gt.Expect(updatedApplicationGroupJSON.String()).To(Equal(tt.expectedConfigGroupJSON))
			if !tt.equalToOriginal {
				gt.Expect(updatedApplicationGroupJSON).NotTo(Equal(originalApplicationGroupJSON))
			} else {
				gt.Expect(updatedApplicationGroupJSON).To(Equal(originalApplicationGroupJSON))
			}
		})
	}
}

func TestAddApplicationCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName         string
		capability       string
		applicationGroup func(ag *cb.ConfigGroup)
		expectedErr      string
	}{
		{
			testName:   "when retrieving existing capabilities",
			capability: "V1_3",
			applicationGroup: func(ag *cb.ConfigGroup) {
				ag.Values = map[string]*cb.ConfigValue{
					CapabilitiesKey: {
						Value: []byte("foobar"),
					},
				}
			},
			expectedErr: "retrieving application capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseApp, _ := baseApplication(t)
			appGroup, err := newApplicationGroupTemplate(baseApp)
			gt.Expect(err).NotTo(HaveOccurred())
			tt.applicationGroup(appGroup)

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						ApplicationGroupKey: appGroup,
					},
				},
			}

			c := New(config)

			err = c.Application().AddCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestRemoveApplicationCapability(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseApp, _ := baseApplication(t)
	appGroup, err := newApplicationGroupTemplate(baseApp)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: appGroup,
			},
		},
	}

	c := New(config)

	expectedConfigGroupJSON := `{
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
				"capabilities": {}
			},
			"version": "0"
		}
	},
	"version": "0"
}
`
	capability := "V1_3"
	err = c.Application().RemoveCapability(capability)
	gt.Expect(err).NotTo(HaveOccurred())

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &peerext.DynamicApplicationGroup{ConfigGroup: c.updated.ChannelGroup.Groups[ApplicationGroupKey]})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConfigGroupJSON))
}

func TestRemoveApplicationCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName         string
		capability       string
		applicationGroup func(ag *cb.ConfigGroup)
		expectedErr      string
	}{
		{
			testName:   "when capability does not exist",
			capability: "V2_0",
			applicationGroup: func(ag *cb.ConfigGroup) {
			},
			expectedErr: "capability not set",
		},
		{
			testName:   "when retrieving existing capabilities",
			capability: "V1_3",
			applicationGroup: func(ag *cb.ConfigGroup) {
				ag.Values = map[string]*cb.ConfigValue{
					CapabilitiesKey: {
						Value: []byte("foobar"),
					},
				}
			},
			expectedErr: "retrieving application capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			baseApp, _ := baseApplication(t)
			appGroup, err := newApplicationGroupTemplate(baseApp)
			gt.Expect(err).NotTo(HaveOccurred())
			tt.applicationGroup(appGroup)

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						ApplicationGroupKey: appGroup,
					},
				},
			}

			c := New(config)

			err = c.Application().RemoveCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestApplicationOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel := Channel{
		Consortium: "SampleConsortium",
		Application: Application{
			Policies:      standardPolicies(),
			Organizations: []Organization{baseApplicationOrg(t)},
		},
	}
	channelGroup, err := newChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())
	orgGroup, err := newApplicationOrgConfigGroup(channel.Application.Organizations[0])
	gt.Expect(err).NotTo(HaveOccurred())
	channelGroup.Groups[ApplicationGroupKey].Groups["Org1"] = orgGroup

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	expectedOrg := channel.Application.Organizations[0]

	tests := []struct {
		name    string
		orgName string
	}{
		{
			name:    "success",
			orgName: "Org1",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			org, err := c.Application().Organization(tc.orgName).Configuration()
			gt.Expect(err).ToNot(HaveOccurred())
			gt.Expect(expectedOrg).To(Equal(org))
		})
	}
}

func TestRemoveApplicationOrg(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel := Channel{
		Consortium: "SampleConsortium",
		Application: Application{
			Policies:      standardPolicies(),
			Organizations: []Organization{baseApplicationOrg(t)},
		},
	}
	channelGroup, err := newChannelGroup(channel)
	gt.Expect(err).NotTo(HaveOccurred())
	orgGroup, err := newOrgConfigGroup(channel.Application.Organizations[0])
	gt.Expect(err).NotTo(HaveOccurred())
	channelGroup.Groups[ApplicationGroupKey].Groups["Org1"] = orgGroup

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	c.Application().RemoveOrganization("Org1")
	gt.Expect(c.updated.ChannelGroup.Groups[ApplicationGroupKey].Groups["Org1"]).To(BeNil())
}

func TestRemoveApplicationOrgPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	applicationGroup := newConfigGroup()

	application, _ := baseApplication(t)

	for _, org := range application.Organizations {
		org.Policies = applicationOrgStandardPolicies()
		org.Policies["TestPolicy"] = Policy{
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		}

		orgGroup, err := newOrgConfigGroup(org)
		gt.Expect(err).NotTo(HaveOccurred())

		applicationGroup.Groups[org.Name] = orgGroup
	}
	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	application.Organizations[0].Policies = applicationOrgStandardPolicies()
	expectedOrgConfigGroup, _ := newOrgConfigGroup(application.Organizations[0])
	expectedPolicies := expectedOrgConfigGroup.Policies

	applicationOrg1 := c.Application().Organization("Org1")
	err := applicationOrg1.RemovePolicy("TestPolicy")
	gt.Expect(err).NotTo(HaveOccurred())

	actualOrg1Policies := applicationOrg1.orgGroup.Policies
	gt.Expect(actualOrg1Policies).To(Equal(expectedPolicies))
}

func TestRemoveApplicationOrgPolicyFailures(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	applicationGroup := newConfigGroup()

	application, _ := baseApplication(t)
	for _, org := range application.Organizations {
		org.Policies = applicationOrgStandardPolicies()
		orgGroup, err := newOrgConfigGroup(org)
		gt.Expect(err).NotTo(HaveOccurred())
		applicationGroup.Groups[org.Name] = orgGroup
	}

	applicationGroup.Groups["Org1"].Policies["TestPolicy"] = &cb.ConfigPolicy{
		Policy: &cb.Policy{
			Type: 15,
		},
	}
	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	err := c.Application().Organization("Org1").RemovePolicy("TestPolicy")
	gt.Expect(err).To(MatchError("unknown policy type: 15"))
}

func TestSetApplicationOrgPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	applicationGroup := newConfigGroup()

	application, _ := baseApplication(t)

	for _, org := range application.Organizations {
		org.Policies = applicationOrgStandardPolicies()

		orgGroup, err := newOrgConfigGroup(org)
		gt.Expect(err).NotTo(HaveOccurred())

		applicationGroup.Groups[org.Name] = orgGroup
	}
	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	application.Organizations[0].Policies = applicationOrgStandardPolicies()
	expectedOrgConfigGroup, _ := newOrgConfigGroup(application.Organizations[0])
	expectedPolicies := expectedOrgConfigGroup.Policies
	expectedPolicies["TestPolicy"] = expectedPolicies[EndorsementPolicyKey]

	applicationOrg1 := c.Application().Organization("Org1")
	err := applicationOrg1.SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "MAJORITY Endorsement"})
	gt.Expect(err).NotTo(HaveOccurred())

	actualOrg1Policies := applicationOrg1.orgGroup.Policies
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(actualOrg1Policies).To(Equal(expectedPolicies))
}

func TestSetApplicationOrgPolicyFailures(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	applicationGroup := newConfigGroup()

	application, _ := baseApplication(t)
	for _, org := range application.Organizations {
		org.Policies = applicationOrgStandardPolicies()

		orgGroup, err := newOrgConfigGroup(org)
		gt.Expect(err).NotTo(HaveOccurred())

		applicationGroup.Groups[org.Name] = orgGroup
	}
	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	err := c.Application().Organization("Org1").SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{})
	gt.Expect(err).To(MatchError("failed to set policy 'TestPolicy': unknown policy type: "))
}

func TestSetApplicationPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	application, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
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
		"TestPolicy": {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
	}

	a := c.Application()
	err = a.SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "MAJORITY Endorsement"})
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := a.Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestSetApplicationPolicyFailures(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	application, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	expectedPolicies := application.Policies
	expectedPolicies["TestPolicy"] = expectedPolicies[EndorsementPolicyKey]

	err = c.Application().SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{})
	gt.Expect(err).To(MatchError("failed to set policy 'TestPolicy': unknown policy type: "))
}

func TestRemoveApplicationPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	application, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())
	applicationGroup.Policies["TestPolicy"] = applicationGroup.Policies[AdminsPolicyKey]

	channelGroup.Groups[ApplicationGroupKey] = applicationGroup
	config := &cb.Config{
		ChannelGroup: channelGroup,
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
	}

	a := c.Application()
	err = a.RemovePolicy("TestPolicy")
	gt.Expect(err).NotTo(HaveOccurred())

	updatedPolicies, err := a.Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedPolicies).To(Equal(expectedPolicies))
}

func TestRemoveApplicationPolicyFailures(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup := newConfigGroup()
	application, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroupTemplate(application)
	gt.Expect(err).NotTo(HaveOccurred())

	applicationGroup.Policies[EndorsementPolicyKey] = &cb.ConfigPolicy{
		Policy: &cb.Policy{
			Type: 15,
		},
	}
	channelGroup.Groups[ApplicationGroupKey] = applicationGroup

	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	err = c.Application().RemovePolicy("TestPolicy")
	gt.Expect(err).To(MatchError("unknown policy type: 15"))
}

func TestApplicationMSP(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	application, _ := baseApplication(t)
	applicationGroup, err := newApplicationGroup(application)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Groups: map[string]*cb.ConfigGroup{
				ApplicationGroupKey: applicationGroup,
			},
		},
	}

	c := New(config)

	msp, err := c.Application().Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(msp).To(Equal(application.Organizations[0].MSP))
}

func TestSetApplicationMSPFailure(t *testing.T) {
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
			orgName:     "Org1",
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
			orgName:     "Org1",
			expectedErr: "invalid root cert: KeyUsage must be x509.KeyUsageCertSign. serial number: 7",
		},
		{
			spec: "root ca cert is not a ca",
			mspMod: func(msp MSP) MSP {
				msp.RootCerts = []*x509.Certificate{
					{
						SerialNumber: big.NewInt(7),
						KeyUsage:     x509.KeyUsageCertSign,
						IsCA:         false,
					},
				}
				return msp
			},
			orgName:     "Org1",
			expectedErr: "invalid root cert: must be a CA certificate. serial number: 7",
		},
		{
			spec: "invalid intermediate ca keyusage",
			mspMod: func(msp MSP) MSP {
				msp.IntermediateCerts = []*x509.Certificate{
					{
						SerialNumber: big.NewInt(7),
						KeyUsage:     x509.KeyUsageKeyAgreement,
					},
				}
				return msp
			},
			orgName:     "Org1",
			expectedErr: "invalid intermediate cert: KeyUsage must be x509.KeyUsageCertSign. serial number: 7",
		},
		{
			spec: "invalid intermediate cert -- not signed by root cert",
			mspMod: func(msp MSP) MSP {
				cert, _ := generateCACertAndPrivateKey(t, "org1.example.com")
				cert.SerialNumber = big.NewInt(7)
				msp.IntermediateCerts = []*x509.Certificate{cert}
				return msp
			},
			orgName:     "Org1",
			expectedErr: "intermediate cert not signed by any root certs of this MSP. serial number: 7",
		},
		{
			spec: "tls root ca cert is not a ca",
			mspMod: func(msp MSP) MSP {
				msp.TLSRootCerts = []*x509.Certificate{
					{
						SerialNumber: big.NewInt(7),
						KeyUsage:     x509.KeyUsageCertSign,
						IsCA:         false,
					},
				}
				return msp
			},
			orgName:     "Org1",
			expectedErr: "invalid tls root cert: must be a CA certificate. serial number: 7",
		},
		{
			spec: "tls intemediate ca cert is not a ca",
			mspMod: func(msp MSP) MSP {
				msp.TLSIntermediateCerts = []*x509.Certificate{
					{
						SerialNumber: big.NewInt(7),
						KeyUsage:     x509.KeyUsageCertSign,
						IsCA:         false,
					},
				}
				return msp
			},
			orgName:     "Org1",
			expectedErr: "invalid tls intermediate cert: must be a CA certificate. serial number: 7",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)
			channelGroup, _, err := baseApplicationChannelGroup(t)
			gt.Expect(err).ToNot(HaveOccurred())
			config := &cb.Config{
				ChannelGroup: channelGroup,
			}

			c := New(config)

			org1MSP, err := c.Application().Organization("Org1").MSP()
			gt.Expect(err).NotTo(HaveOccurred())

			org1MSP = tc.mspMod(org1MSP)
			err = c.Application().Organization(tc.orgName).SetMSP(org1MSP)
			gt.Expect(err).To(MatchError(tc.expectedErr))
		})
	}
}

func TestCreateApplicationMSPCRL(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, privKeys, err := baseApplicationChannelGroup(t)
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	org1MSP, err := c.Application().Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org1RootCert := org1MSP.RootCerts[0]
	org1PrivKey := privKeys[0]

	// update org2MSP to include an intemediate cert that is different
	// from the root cert
	org2MSP, err := c.Application().Organization("Org2").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org2Cert := org2MSP.RootCerts[0]
	org2PrivKey := privKeys[1]
	org2IntermediateCert, org2IntermediatePrivKey := generateIntermediateCACertAndPrivateKey(t, "org2.example.com", org2Cert, org2PrivKey)
	org2MSP.IntermediateCerts = append(org2MSP.IntermediateCerts, org2IntermediateCert)
	err = c.Application().Organization("Org2").SetMSP(org2MSP)
	gt.Expect(err).NotTo(HaveOccurred())

	tests := []struct {
		spec             string
		orgName          string
		caCert           *x509.Certificate
		caPrivKey        *ecdsa.PrivateKey
		numCertsToRevoke int
	}{
		{
			spec:             "create CRL using a root cert",
			orgName:          "Org1",
			caCert:           org1RootCert,
			caPrivKey:        org1PrivKey,
			numCertsToRevoke: 2,
		},
		{
			spec:             "create CRL using an intermediate cert",
			orgName:          "Org2",
			caCert:           org2IntermediateCert,
			caPrivKey:        org2IntermediatePrivKey,
			numCertsToRevoke: 1,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)
			certsToRevoke := make([]*x509.Certificate, tc.numCertsToRevoke)
			for i := 0; i < tc.numCertsToRevoke; i++ {
				certToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, tc.orgName, tc.caCert, tc.caPrivKey)
				certsToRevoke[i] = certToRevoke
			}
			signingIdentity := &SigningIdentity{
				Certificate: tc.caCert,
				PrivateKey:  tc.caPrivKey,
				MSPID:       "MSPID",
			}
			crl, err := c.Application().Organization(tc.orgName).CreateMSPCRL(signingIdentity, certsToRevoke...)
			gt.Expect(err).NotTo(HaveOccurred())
			err = tc.caCert.CheckCRLSignature(crl)
			gt.Expect(err).NotTo(HaveOccurred())
			gt.Expect(crl.TBSCertList.RevokedCertificates).To(HaveLen(tc.numCertsToRevoke))
			for i := 0; i < tc.numCertsToRevoke; i++ {
				gt.Expect(crl.TBSCertList.RevokedCertificates[i].SerialNumber).To(Equal(certsToRevoke[i].SerialNumber))
			}
		})
	}
}

func TestCreateApplicationMSPCRLFailure(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, privKeys, err := baseApplicationChannelGroup(t)
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	org1MSP, err := c.Application().Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org1Cert := org1MSP.RootCerts[0]
	org1PrivKey := privKeys[0]
	org1CertToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, "org1.example.com", org1Cert, org1PrivKey)

	org2MSP, err := c.Application().Organization("Org2").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org2Cert := org2MSP.RootCerts[0]
	org2PrivKey := privKeys[1]
	org2CertToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, "org2.example.com", org2Cert, org2PrivKey)

	signingIdentity := &SigningIdentity{
		Certificate: org1Cert,
		PrivateKey:  org1PrivKey,
	}
	tests := []struct {
		spec            string
		mspMod          func(MSP) MSP
		signingIdentity *SigningIdentity
		certToRevoke    *x509.Certificate
		orgName         string
		expectedErr     string
	}{
		{
			spec:    "signing cert is not a root/intermediate cert for msp",
			orgName: "Org1",
			signingIdentity: &SigningIdentity{
				Certificate: org2Cert,
				PrivateKey:  org2PrivKey,
			},
			certToRevoke: org1CertToRevoke,
			expectedErr:  "signing cert is not a root/intermediate cert for this MSP: MSPID",
		},
		{
			spec:            "certificate not issued by this MSP",
			orgName:         "Org1",
			signingIdentity: signingIdentity,
			certToRevoke:    org2CertToRevoke,
			expectedErr:     fmt.Sprintf("certificate not issued by this MSP. serial number: %d", org2CertToRevoke.SerialNumber),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			newCRL, err := c.Application().Organization(tc.orgName).CreateMSPCRL(tc.signingIdentity, tc.certToRevoke)
			gt.Expect(err).To(MatchError(tc.expectedErr))
			gt.Expect(newCRL).To(BeNil())
		})
	}
}

func TestSetApplicationMSP(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, privateKeys, err := baseApplicationChannelGroup(t)
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	c := New(config)

	org1MSP, err := c.Application().Organization("Org1").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org2MSP, err := c.Application().Organization("Org2").MSP()
	gt.Expect(err).NotTo(HaveOccurred())
	org1CertBase64, org1CRLBase64 := certCRLBase64(t, org1MSP)
	org2CertBase64, org2CRLBase64 := certCRLBase64(t, org2MSP)

	newRootCert, newRootPrivKey := generateCACertAndPrivateKey(t, "anotherca-org1.example.com")
	newRootCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newRootCert))
	org1MSP.RootCerts = append(org1MSP.RootCerts, newRootCert)

	newIntermediateCert, _ := generateIntermediateCACertAndPrivateKey(t, "anotherca-org1.example.com", newRootCert, newRootPrivKey)
	newIntermediateCertBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(newIntermediateCert))
	org1MSP.IntermediateCerts = append(org1MSP.IntermediateCerts, newIntermediateCert)

	cert := org1MSP.RootCerts[0]
	privKey := privateKeys[0]
	certToRevoke, _ := generateCertAndPrivateKeyFromCACert(t, "org1.example.com", cert, privKey)
	signingIdentity := &SigningIdentity{
		Certificate: cert,
		PrivateKey:  privKey,
		MSPID:       "MSPID",
	}
	newCRL, err := c.Application().Organization("Org1").CreateMSPCRL(signingIdentity, certToRevoke)
	gt.Expect(err).NotTo(HaveOccurred())
	pemNewCRL, err := pemEncodeCRL(newCRL)
	gt.Expect(err).NotTo(HaveOccurred())
	newCRLBase64 := base64.StdEncoding.EncodeToString(pemNewCRL)
	org1MSP.RevocationList = append(org1MSP.RevocationList, newCRL)

	err = c.Application().Organization("Org1").SetMSP(org1MSP)
	gt.Expect(err).NotTo(HaveOccurred())

	expectedConfigJSON := fmt.Sprintf(`
{
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
			}
		},
		"mod_policy": "",
		"policies": {},
		"values": {},
		"version": "0"
	},
	"sequence": "0"
}
`, org1CertBase64, newIntermediateCertBase64, org1CRLBase64, newCRLBase64, newRootCertBase64, org2CertBase64, org2CRLBase64)

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, c.updated)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(MatchJSON(expectedConfigJSON))
}

func baseApplication(t *testing.T) (Application, []*ecdsa.PrivateKey) {
	org1BaseMSP, org1PrivKey := baseMSP(t)
	org2BaseMSP, org2PrivKey := baseMSP(t)
	return Application{
		Policies: standardPolicies(),
		Organizations: []Organization{
			{
				Name:     "Org1",
				Policies: applicationOrgStandardPolicies(),
				MSP:      org1BaseMSP,
			},
			{
				Name:     "Org2",
				Policies: applicationOrgStandardPolicies(),
				MSP:      org2BaseMSP,
			},
		},
		Capabilities: []string{
			"V1_3",
		},
		ACLs: map[string]string{
			"acl1": "hi",
		},
	}, []*ecdsa.PrivateKey{org1PrivKey, org2PrivKey}
}
