/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/commonext"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestChannelCapabilities(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	expectedCapabilities := []string{"V1_3"}

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Values: map[string]*cb.ConfigValue{},
		},
	}

	err := setValue(config.ChannelGroup, capabilitiesValue(expectedCapabilities), AdminsPolicyKey)
	gt.Expect(err).NotTo(HaveOccurred())

	c := New(config)

	channelCapabilities, err := c.Channel().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(channelCapabilities).To(Equal(expectedCapabilities))

	// Delete the capabilities key and assert retrieval to return nil
	delete(c.Channel().channelGroup.Values, CapabilitiesKey)
	channelCapabilities, err = c.Channel().Capabilities()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(channelCapabilities).To(BeNil())
}

func TestSetChannelCapability(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Values: map[string]*cb.ConfigValue{
				CapabilitiesKey: {},
			},
		},
	}

	c := New(config)

	expectedConfigGroupJSON := `{
	"groups": {},
	"mod_policy": "",
	"policies": {},
	"values": {
		"Capabilities": {
			"mod_policy": "Admins",
			"value": {
				"capabilities": {
					"V3_0": {}
				}
			},
			"version": "0"
		}
	},
	"version": "0"
}
`

	err := c.Channel().AddCapability("V3_0")
	gt.Expect(err).NotTo(HaveOccurred())

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &commonext.DynamicChannelGroup{ConfigGroup: c.Channel().channelGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConfigGroupJSON))
}

func TestSetChannelCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		capability  string
		config      *cb.Config
		expectedErr string
	}{
		{
			testName:   "when retrieving existing capabilities",
			capability: "V2_0",
			config: &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Values: map[string]*cb.ConfigValue{
						CapabilitiesKey: {
							Value: []byte("foobar"),
						},
					},
				},
			},
			expectedErr: "retrieving channel capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			c := New(tt.config)

			err := c.Channel().AddCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestRemoveChannelCapability(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Values: map[string]*cb.ConfigValue{
				CapabilitiesKey: {
					Value: marshalOrPanic(&cb.Capabilities{Capabilities: map[string]*cb.Capability{
						"V3_0": {},
					}}),
					ModPolicy: AdminsPolicyKey,
				},
			},
		},
	}

	c := New(config)

	expectedConfigGroupJSON := `{
	"groups": {},
	"mod_policy": "",
	"policies": {},
	"values": {
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

	err := c.Channel().RemoveCapability("V3_0")
	gt.Expect(err).NotTo(HaveOccurred())

	buf := bytes.Buffer{}
	err = protolator.DeepMarshalJSON(&buf, &commonext.DynamicChannelGroup{ConfigGroup: c.Channel().channelGroup})
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(buf.String()).To(Equal(expectedConfigGroupJSON))
}

func TestRemoveChannelCapabilityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		capability  string
		config      *cb.Config
		expectedErr string
	}{
		{
			testName:   "when capability does not exist",
			capability: "V2_0",
			config: &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Values: map[string]*cb.ConfigValue{
						CapabilitiesKey: {
							ModPolicy: AdminsPolicyKey,
						},
					},
				},
			},
			expectedErr: "capability not set",
		},
		{
			testName:   "when retrieving existing capabilities",
			capability: "V2_0",
			config: &cb.Config{
				ChannelGroup: &cb.ConfigGroup{
					Values: map[string]*cb.ConfigValue{
						CapabilitiesKey: {
							Value: []byte("foobar"),
						},
					},
				},
			},
			expectedErr: "retrieving channel capabilities: unmarshaling capabilities: proto: can't skip unknown wire type 6",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			c := New(tt.config)

			err := c.Channel().RemoveCapability(tt.capability)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestSetChannelPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, err := baseApplicationChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channel,
	}
	c := New(config)

	expectedPolicies := map[string]Policy{
		"TestPolicy": {Type: ImplicitMetaPolicyType, Rule: "ANY Readers"},
	}

	err = c.Channel().SetPolicy(AdminsPolicyKey, "TestPolicy", Policy{Type: ImplicitMetaPolicyType, Rule: "ANY Readers"})
	gt.Expect(err).NotTo(HaveOccurred())

	updatedChannelPolicy, err := getPolicies(c.updated.ChannelGroup.Policies)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedChannelPolicy).To(Equal(expectedPolicies))

	baseChannel := c.original.ChannelGroup
	gt.Expect(baseChannel.Policies).To(HaveLen(0))
	gt.Expect(baseChannel.Policies["TestPolicy"]).To(BeNil())
}

func TestRemoveChannelPolicy(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, err := baseApplicationChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channel,
	}
	policies := standardPolicies()
	err = setPolicies(channel, policies, AdminsPolicyKey)
	gt.Expect(err).NotTo(HaveOccurred())
	c := New(config)

	expectedPolicies := map[string]Policy{
		"Admins": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
	}

	err = c.Channel().RemovePolicy(ReadersPolicyKey)
	gt.Expect(err).NotTo(HaveOccurred())

	updatedChannelPolicy, err := c.Channel().Policies()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(updatedChannelPolicy).To(Equal(expectedPolicies))

	originalChannel := c.original.ChannelGroup
	gt.Expect(originalChannel.Policies).To(HaveLen(3))
	gt.Expect(originalChannel.Policies[ReadersPolicyKey]).ToNot(BeNil())
}

func TestRemoveChannelPolicyFailures(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channel, _, err := baseApplicationChannelGroup(t)
	gt.Expect(err).NotTo(HaveOccurred())

	config := &cb.Config{
		ChannelGroup: channel,
	}
	policies := standardPolicies()
	err = setPolicies(channel, policies, AdminsPolicyKey)
	gt.Expect(err).NotTo(HaveOccurred())
	channel.Policies[ReadersPolicyKey] = &cb.ConfigPolicy{
		Policy: &cb.Policy{
			Type: 15,
		},
	}
	c := New(config)

	err = c.Channel().RemovePolicy(ReadersPolicyKey)
	gt.Expect(err).To(MatchError("unknown policy type: 15"))
}

func TestRemoveLegacyOrdererAddresses(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	config := &cb.Config{
		ChannelGroup: &cb.ConfigGroup{
			Values: map[string]*cb.ConfigValue{
				OrdererAddressesKey: {
					ModPolicy: AdminsPolicyKey,
					Value: marshalOrPanic(&cb.OrdererAddresses{
						Addresses: []string{"127.0.0.1:8050"},
					}),
				},
			},
		},
	}

	c := New(config)

	c.Channel().RemoveLegacyOrdererAddresses()

	_, exists := c.Channel().channelGroup.Values[OrdererAddressesKey]
	gt.Expect(exists).To(BeFalse())
}
