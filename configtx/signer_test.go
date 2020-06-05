/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestSign(t *testing.T) {
	t.Parallel()

	cert, privateKey := generateCACertAndPrivateKey(t, "org1.example.com")

	tests := []struct {
		spec        string
		privateKey  crypto.PrivateKey
		reader      io.Reader
		msg         []byte
		expectedErr string
	}{
		{
			spec:        "success",
			privateKey:  privateKey,
			reader:      rand.Reader,
			msg:         []byte("banana"),
			expectedErr: "",
		},
		{
			spec:        "unsupported rsa private key",
			privateKey:  &rsa.PrivateKey{},
			reader:      rand.Reader,
			msg:         []byte("banana"),
			expectedErr: "signing with private key of type *rsa.PrivateKey not supported",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)

			signingIdentity := &SigningIdentity{
				Certificate: cert,
				PrivateKey:  tc.privateKey,
				MSPID:       "test-msp",
			}

			signature, err := signingIdentity.Sign(tc.reader, tc.msg, nil)
			if tc.expectedErr == "" {
				gt.Expect(err).NotTo(HaveOccurred())
				gt.Expect(signature).NotTo(BeNil())
				sig := &ecdsaSignature{}
				_, err := asn1.Unmarshal(signature, sig)
				gt.Expect(err).NotTo(HaveOccurred())
				hash := sha256.New()
				hash.Write(tc.msg)
				digest := hash.Sum(nil)
				valid := ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest, sig.R, sig.S)
				gt.Expect(valid).To(BeTrue())
			} else {
				gt.Expect(err).To(MatchError(tc.expectedErr))
				gt.Expect(signature).To(BeNil())
			}
		})
	}
}

func TestPublic(t *testing.T) {
	gt := NewGomegaWithT(t)

	cert, privateKey := generateCACertAndPrivateKey(t, "org1.example.com")
	signingIdentity := &SigningIdentity{
		Certificate: cert,
		PrivateKey:  privateKey,
	}
	gt.Expect(signingIdentity.Public()).To(Equal(cert.PublicKey))
}

func TestCreateSignature(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	cert, privateKey := generateCACertAndPrivateKey(t, "org1.example.com")
	signingIdentity := SigningIdentity{
		Certificate: cert,
		PrivateKey:  privateKey,
		MSPID:       "test-msp",
	}

	configSignature, err := signingIdentity.CreateConfigSignature([]byte("config"))
	gt.Expect(err).NotTo(HaveOccurred())

	sh, err := signingIdentity.signatureHeader()
	gt.Expect(err).NotTo(HaveOccurred())
	expectedCreator := sh.Creator
	signatureHeader := &cb.SignatureHeader{}
	err = proto.Unmarshal(configSignature.SignatureHeader, signatureHeader)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(signatureHeader.Creator).To(Equal(expectedCreator))
}

func TestSignEnvelope(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	// create signingIdentity
	cert, privateKey := generateCACertAndPrivateKey(t, "org1.example.com")
	signingIdentity := SigningIdentity{
		Certificate: cert,
		PrivateKey:  privateKey,
		MSPID:       "test-msp",
	}

	// create detached config signature
	configUpdate := &cb.ConfigUpdate{
		ChannelId: "testchannel",
	}
	marshaledUpdate, err := proto.Marshal(configUpdate)
	gt.Expect(err).NotTo(HaveOccurred())
	configSignature, err := signingIdentity.CreateConfigSignature(marshaledUpdate)
	gt.Expect(err).NotTo(HaveOccurred())

	// create signed config envelope
	env, err := NewEnvelope(marshaledUpdate, configSignature)
	gt.Expect(err).NotTo(HaveOccurred())
	err = signingIdentity.SignEnvelope(env)
	gt.Expect(err).NotTo(HaveOccurred())

	payload := &cb.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	gt.Expect(err).NotTo(HaveOccurred())
	// check header channel ID equal
	channelHeader := &cb.ChannelHeader{}
	err = proto.Unmarshal(payload.GetHeader().GetChannelHeader(), channelHeader)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(channelHeader.ChannelId).To(Equal(configUpdate.ChannelId))
	// check config update envelope signatures are equal
	configEnv := &cb.ConfigUpdateEnvelope{}
	err = proto.Unmarshal(payload.Data, configEnv)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(len(configEnv.Signatures)).To(Equal(1))
	expectedSignatures := configEnv.Signatures[0]
	gt.Expect(expectedSignatures.SignatureHeader).To(Equal(configSignature.SignatureHeader))
	gt.Expect(expectedSignatures.Signature).To(Equal(configSignature.Signature))
}

func TestSignEnvelopeWithAnchorPeers(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	baseApplicationConf, _ := baseApplication(t)

	applicationGroup, err := newApplicationGroup(baseApplicationConf)
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

	err = c.Application().Organization("Org1").AddAnchorPeer(newOrg1AnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	err = c.Application().Organization("Org2").AddAnchorPeer(newOrg2AnchorPeer)
	gt.Expect(err).NotTo(HaveOccurred())

	// create signingIdentity
	cert, privateKey := generateCACertAndPrivateKey(t, "org1.example.com")
	signingIdentity := SigningIdentity{
		Certificate: cert,
		PrivateKey:  privateKey,
		MSPID:       "test-msp",
	}

	configUpdate, err := c.ComputeMarshaledUpdate("fake-channel")
	gt.Expect(err).NotTo(HaveOccurred())

	configSignature, err := signingIdentity.CreateConfigSignature(configUpdate)
	gt.Expect(err).NotTo(HaveOccurred())

	// create signed config envelope
	env, err := NewEnvelope(configUpdate, configSignature)
	gt.Expect(err).NotTo(HaveOccurred())
	err = signingIdentity.SignEnvelope(env)
	gt.Expect(err).NotTo(HaveOccurred())

	// check envelope signature is valid
	// env.Signature
	sig := &ecdsaSignature{}
	_, err = asn1.Unmarshal(env.Signature, sig)
	gt.Expect(err).NotTo(HaveOccurred())
	hash := sha256.New()
	hash.Write(env.Payload)
	digest := hash.Sum(nil)
	valid := ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest, sig.R, sig.S)
	gt.Expect(valid).To(BeTrue())

	payload := &cb.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	gt.Expect(err).NotTo(HaveOccurred())

	configUpdateEnvelope := &cb.ConfigUpdateEnvelope{}
	err = proto.Unmarshal(payload.Data, configUpdateEnvelope)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(configUpdateEnvelope.Signatures).To(HaveLen(1))

	sig = &ecdsaSignature{}
	configSig := configUpdateEnvelope.Signatures[0]
	_, err = asn1.Unmarshal(configSig.Signature, sig)
	gt.Expect(err).NotTo(HaveOccurred())
	hash = sha256.New()
	hash.Write(concatenateBytes(configSig.SignatureHeader, configUpdateEnvelope.ConfigUpdate))
	digest = hash.Sum(nil)
	valid = ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest, sig.R, sig.S)
	gt.Expect(valid).To(BeTrue())
}

func TestToLowS(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()
	halfOrder := new(big.Int).Div(curve.Params().N, big.NewInt(2))

	for _, test := range []struct {
		name        string
		sig         ecdsaSignature
		expectedSig ecdsaSignature
	}{
		{
			name: "HighS",
			sig: ecdsaSignature{
				R: big.NewInt(1),
				// set S to halfOrder + 1
				S: new(big.Int).Add(halfOrder, big.NewInt(1)),
			},
			// expected signature should be (sig.R, -sig.S mod N)
			expectedSig: ecdsaSignature{
				R: big.NewInt(1),
				S: new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Add(halfOrder, big.NewInt(1))), curve.Params().N),
			},
		},
		{
			name: "LowS",
			sig: ecdsaSignature{
				R: big.NewInt(1),
				// set S to halfOrder - 1
				S: new(big.Int).Sub(halfOrder, big.NewInt(1)),
			},
			// expected signature should be sig
			expectedSig: ecdsaSignature{
				R: big.NewInt(1),
				S: new(big.Int).Sub(halfOrder, big.NewInt(1)),
			},
		},
		{
			name: "HalfOrder",
			sig: ecdsaSignature{
				R: big.NewInt(1),
				// set S to halfOrder
				S: halfOrder,
			},
			// expected signature should be sig
			expectedSig: ecdsaSignature{
				R: big.NewInt(1),
				S: halfOrder,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)
			curve := elliptic.P256()
			key := ecdsa.PublicKey{
				Curve: curve,
			}
			gt.Expect(toLowS(key, test.sig), test.expectedSig)
		})
	}
}

// generateCACertAndPrivateKey returns CA cert and private key.
func generateCACertAndPrivateKey(t *testing.T, orgName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	serialNumber := generateSerialNumber(t)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "ca." + orgName,
			Organization: []string{orgName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertAndPrivateKey(t, template, template, nil)
}

func generateIntermediateCACertAndPrivateKey(t *testing.T, orgName string, rootCACert *x509.Certificate, rootPrivKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	serialNumber := generateSerialNumber(t)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "intermediateca." + orgName,
			Organization: []string{orgName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return generateCertAndPrivateKey(t, template, rootCACert, rootPrivKey)
}

// generateCertAndPrivateKeyFromCACert returns a cert and private key signed by the given CACert.
func generateCertAndPrivateKeyFromCACert(t *testing.T, orgName string, caCert *x509.Certificate, privateKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	serialNumber := generateSerialNumber(t)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "user." + orgName,
			Organization: []string{orgName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return generateCertAndPrivateKey(t, template, caCert, privateKey)
}

func generateCertAndPrivateKey(t *testing.T, template, parent *x509.Certificate, parentPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	gt := NewGomegaWithT(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gt.Expect(err).NotTo(HaveOccurred())

	if parentPriv == nil {
		// create self-signed cert
		parentPriv = priv
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, parentPriv)
	gt.Expect(err).NotTo(HaveOccurred())

	cert, err := x509.ParseCertificate(derBytes)
	gt.Expect(err).NotTo(HaveOccurred())

	return cert, priv
}

// generateSerialNumber returns a random serialNumber
func generateSerialNumber(t *testing.T) *big.Int {
	gt := NewGomegaWithT(t)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	gt.Expect(err).NotTo(HaveOccurred())

	return serialNumber
}
