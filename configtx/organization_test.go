/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/ordererext"
	. "github.com/onsi/gomega"
)

func TestOrganization(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	expectedOrg := baseApplicationOrg(t)
	expectedOrg.AnchorPeers = nil
	orgGroup, err := newOrgConfigGroup(expectedOrg)
	gt.Expect(err).NotTo(HaveOccurred())

	org, err := getOrganization(orgGroup, "Org1")
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(expectedOrg).To(Equal(org))
}

func TestNewOrgConfigGroup(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		gt := NewGomegaWithT(t)

		baseSystemChannelProfile, _, _ := baseSystemChannelProfile(t)
		org := baseSystemChannelProfile.Orderer.Organizations[0]
		configGroup, err := newOrdererOrgConfigGroup(org)
		gt.Expect(err).NotTo(HaveOccurred())

		certBase64, crlBase64 := certCRLBase64(t, org.MSP)

		// The organization is from network.BasicSolo Profile
		// configtxgen -printOrg Org1
		expectedPrintOrg := fmt.Sprintf(`
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

		buf := bytes.Buffer{}
		err = protolator.DeepMarshalJSON(&buf, &ordererext.DynamicOrdererOrgGroup{ConfigGroup: configGroup})
		gt.Expect(err).NotTo(HaveOccurred())

		gt.Expect(buf.String()).To(MatchJSON(expectedPrintOrg))
	})
}

func TestNewOrgConfigGroupFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	baseSystemChannelProfile, _, _ := baseSystemChannelProfile(t)
	baseOrg := baseSystemChannelProfile.Orderer.Organizations[0]
	baseOrg.Policies = nil

	configGroup, err := newOrgConfigGroup(baseOrg)
	gt.Expect(configGroup).To(BeNil())
	gt.Expect(err).To(MatchError("no policies defined"))
}

func baseApplicationOrg(t *testing.T) Organization {
	msp, _ := baseMSP(t)
	return Organization{
		Name:     "Org1",
		Policies: standardPolicies(),
		MSP:      msp,
		AnchorPeers: []Address{
			{Host: "host3", Port: 123},
		},
	}
}
