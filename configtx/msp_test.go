/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx/membership"
	"github.com/hyperledger/fabric-config/protolator"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
	. "github.com/onsi/gomega"
)

func TestMSPConfigurationFailures(t *testing.T) {
	t.Parallel()

	badCert := &x509.Certificate{}

	tests := []struct {
		name           string
		orgType        string
		consortiumName string
		orgName        string
		mspMod         func(*MSP)
		expectedErr    string
	}{
		{
			name:    "Bad root cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				badCert := &x509.Certificate{}
				msp.RootCerts = append(msp.RootCerts, badCert)
			},
			expectedErr: "parsing root certs: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad intermediate cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.IntermediateCerts = append(msp.IntermediateCerts, badCert)
			},
			expectedErr: "parsing intermediate certs: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad admin cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.Admins = append(msp.Admins, badCert)
			},
			expectedErr: "parsing admin certs: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad OU Identifier cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.OrganizationalUnitIdentifiers[0].Certificate = badCert
			},
			expectedErr: "parsing ou identifiers: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad tls root cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.TLSRootCerts = append(msp.TLSRootCerts, badCert)
			},
			expectedErr: "parsing tls root certs: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad tls intermediate cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.TLSIntermediateCerts = append(msp.TLSIntermediateCerts, badCert)
			},
			expectedErr: "parsing tls intermediate certs: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad Client OU Identifier cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.NodeOUs.ClientOUIdentifier.Certificate = badCert
			},
			expectedErr: "parsing client ou identifier cert: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad Peer OU Identifier cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.NodeOUs.PeerOUIdentifier.Certificate = badCert
			},
			expectedErr: "parsing peer ou identifier cert: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad Admin OU Identifier cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.NodeOUs.AdminOUIdentifier.Certificate = badCert
			},
			expectedErr: "parsing admin ou identifier cert: asn1: syntax error: sequence truncated",
		},
		{
			name:    "Bad Orderer OU Identifier cert",
			orgType: OrdererGroupKey,
			orgName: "OrdererOrg",
			mspMod: func(msp *MSP) {
				msp.NodeOUs.OrdererOUIdentifier.Certificate = badCert
			},
			expectedErr: "parsing orderer ou identifier cert: asn1: syntax error: sequence truncated",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			consortiums, _ := baseConsortiums(t)
			consortiumsGroup, err := newConsortiumsGroup(consortiums)
			gt.Expect(err).NotTo(HaveOccurred())

			orderer, _ := baseSoloOrderer(t)
			ordererGroup, err := newOrdererGroup(orderer)
			gt.Expect(err).NotTo(HaveOccurred())

			application, _ := baseApplication(t)
			applicationGroup, err := newApplicationGroup(application)
			gt.Expect(err).NotTo(HaveOccurred())

			config := &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Groups: map[string]*cb.ConfigGroup{
						ConsortiumsGroupKey: consortiumsGroup,
						OrdererGroupKey:     ordererGroup,
						ApplicationGroupKey: applicationGroup,
					},
				},
			}

			c := &ConfigTx{
				original: config,
				updated:  config,
			}
			if tt.mspMod != nil && tt.orgType != ConsortiumsGroupKey {
				baseMSP, _ := baseMSP(t)

				tt.mspMod(&baseMSP)

				orgGroup := c.updated.ChannelGroup.Groups[tt.orgType].Groups[tt.orgName]
				fabricMSPConfig, err := baseMSP.toProto()
				gt.Expect(err).NotTo(HaveOccurred())

				conf, err := proto.Marshal(fabricMSPConfig)
				gt.Expect(err).NotTo(HaveOccurred())

				mspConfig := &mb.MSPConfig{
					Config: conf,
				}

				err = setValue(orgGroup, mspValue(mspConfig), AdminsPolicyKey)
				gt.Expect(err).NotTo(HaveOccurred())
			}

			switch tt.orgType {
			case ApplicationGroupKey:
				_, err := c.Application().Organization(tt.orgName).MSP()
				gt.Expect(err).To(MatchError(tt.expectedErr))
			case OrdererGroupKey:
				_, err := c.Orderer().Organization(tt.orgName).MSP()
				gt.Expect(err).To(MatchError(tt.expectedErr))
			case ConsortiumsGroupKey:
				_, err := c.Consortium(tt.consortiumName).Organization(tt.orgName).MSP()
				gt.Expect(err).To(MatchError(tt.expectedErr))
			default:
				t.Fatalf("invalid org type %s", tt.orgType)
			}
		})
	}
}

func TestMSPToProto(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	msp, _ := baseMSP(t)
	certBase64, crlBase64 := certCRLBase64(t, msp)

	expectedFabricMSPConfigProtoJSON := fmt.Sprintf(`
{
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
}
`, certBase64, crlBase64)
	expectedFabricMSPConfigProto := &mb.FabricMSPConfig{}
	err := protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedFabricMSPConfigProtoJSON), expectedFabricMSPConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	fabricMSPConfigProto, err := msp.toProto()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(fabricMSPConfigProto).To(Equal(expectedFabricMSPConfigProto))
}

func TestMSPToProtoNoNodeOUs(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	msp, _ := baseMSP(t)
	msp.NodeOUs = membership.NodeOUs{}
	certBase64, crlBase64 := certCRLBase64(t, msp)

	expectedFabricMSPConfigProtoJSON := fmt.Sprintf(`
{
	"admins": [
		"%[1]s"
	],
	"crypto_config": {
		"identity_identifier_hash_function": "SHA256",
		"signature_hash_family": "SHA3"
	},
	"fabric_node_ous": null,
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
}
`, certBase64, crlBase64)
	expectedFabricMSPConfigProto := &mb.FabricMSPConfig{}
	err := protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedFabricMSPConfigProtoJSON), expectedFabricMSPConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	fabricMSPConfigProto, err := msp.toProto()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(fabricMSPConfigProto).To(Equal(expectedFabricMSPConfigProto))
}

func TestParseCertificateFromBytesFailure(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	errCert := `
-----END CERTIFICATE-----
`

	_, err := parseCertificateFromBytes([]byte(errCert))
	gt.Expect(err).NotTo(BeNil())
	gt.Expect(err.Error()).To(ContainSubstring("no PEM data found in cert["))

	_, err = parseCertificateFromBytes(nil)
	gt.Expect(err).To(MatchError("no PEM data found in cert[]"))
}

func TestParseCRLFailure(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	errCRL := `
-----END X509 CRL-----
`

	_, err := parseCRL([][]byte{[]byte(errCRL)})
	gt.Expect(err).NotTo(BeNil())
	gt.Expect(err.Error()).To(ContainSubstring("no PEM data found in CRL["))

	_, err = parseCRL([][]byte{nil, []byte(errCRL)})
	gt.Expect(err).To(MatchError("no PEM data found in CRL[]"))
}

func TestParsePrivateKeyFromBytesFailure(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	errPrivateKey := `
-----END EC PRIVATE KEY-----
`

	_, err := parsePrivateKeyFromBytes([]byte(errPrivateKey))
	gt.Expect(err).NotTo(BeNil())
	gt.Expect(err.Error()).To(ContainSubstring("no PEM data found in private key["))
}

func baseMSP(t *testing.T) (MSP, *ecdsa.PrivateKey) {
	gt := NewGomegaWithT(t)

	cert, privKey := generateCACertAndPrivateKey(t, "org1.example.com")
	crlBytes, err := cert.CreateCRL(rand.Reader, privKey, nil, time.Now(), time.Now().Add(YEAR))
	gt.Expect(err).NotTo(HaveOccurred())

	crl, err := x509.ParseCRL(crlBytes)
	gt.Expect(err).NotTo(HaveOccurred())

	return MSP{
		Name:              "MSPID",
		RootCerts:         []*x509.Certificate{cert},
		IntermediateCerts: []*x509.Certificate{cert},
		Admins:            []*x509.Certificate{cert},
		RevocationList:    []*pkix.CertificateList{crl},
		OrganizationalUnitIdentifiers: []membership.OUIdentifier{
			{
				Certificate:                  cert,
				OrganizationalUnitIdentifier: "OUID",
			},
		},
		CryptoConfig: membership.CryptoConfig{
			SignatureHashFamily:            "SHA3",
			IdentityIdentifierHashFunction: "SHA256",
		},
		TLSRootCerts:         []*x509.Certificate{cert},
		TLSIntermediateCerts: []*x509.Certificate{cert},
		NodeOUs: membership.NodeOUs{
			ClientOUIdentifier: membership.OUIdentifier{
				Certificate:                  cert,
				OrganizationalUnitIdentifier: "OUID",
			},
			PeerOUIdentifier: membership.OUIdentifier{
				Certificate:                  cert,
				OrganizationalUnitIdentifier: "OUID",
			},
			AdminOUIdentifier: membership.OUIdentifier{
				Certificate:                  cert,
				OrganizationalUnitIdentifier: "OUID",
			},
			OrdererOUIdentifier: membership.OUIdentifier{
				Certificate:                  cert,
				OrganizationalUnitIdentifier: "OUID",
			},
		},
	}, privKey
}

// certCRLBase64 returns a base64 encoded representation of
// the first root certificate, the private key, and the first revocation list
// for the specified MSP. These are intended for use when formatting the
// expected config in JSON format.
func certCRLBase64(t *testing.T, msp MSP) (string, string) {
	gt := NewGomegaWithT(t)

	cert := msp.RootCerts[0]
	crl := msp.RevocationList[0]

	certBase64 := base64.StdEncoding.EncodeToString(pemEncodeX509Certificate(cert))
	pemCRLBytes, err := buildPemEncodedRevocationList([]*pkix.CertificateList{crl})
	gt.Expect(err).NotTo(HaveOccurred())
	crlBase64 := base64.StdEncoding.EncodeToString(pemCRLBytes[0])

	return certBase64, crlBase64

}
