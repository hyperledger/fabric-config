/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package configtx

import (
	"testing"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	. "github.com/onsi/gomega"
)

func TestPolicies(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	expectedPolicies := map[string]Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ALL Member",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Member",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Member",
		},
		"SignaturePolicy": {
			Type: SignaturePolicyType,
			Rule: "AND('Org1.member', 'Org2.client', OR('Org3.peer', 'Org3.admin'), OUTOF(2, 'Org4.member', 'Org4.peer', 'Org4.admin'))",
		},
	}
	orgGroup := newConfigGroup()
	err := setPolicies(orgGroup, expectedPolicies, AdminsPolicyKey)
	gt.Expect(err).NotTo(HaveOccurred())

	policies, err := getPolicies(orgGroup.Policies)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(expectedPolicies).To(Equal(policies))

	policies, err = getPolicies(nil)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(map[string]Policy{}).To(Equal(policies))
}

func TestSetConsortiumChannelCreationPolicy(t *testing.T) {
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

	updatedPolicy := Policy{Type: ImplicitMetaPolicyType, Rule: "MAJORITY Admins"}

	consortium1 := c.Consortium("Consortium1")
	err = consortium1.SetChannelCreationPolicy(updatedPolicy)
	gt.Expect(err).NotTo(HaveOccurred())

	creationPolicy := consortium1.consortiumGroup.Values[ChannelCreationPolicyKey]
	policy := &cb.Policy{}
	err = proto.Unmarshal(creationPolicy.Value, policy)
	gt.Expect(err).NotTo(HaveOccurred())
	imp := &cb.ImplicitMetaPolicy{}
	err = proto.Unmarshal(policy.Value, imp)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(imp.Rule).To(Equal(cb.ImplicitMetaPolicy_MAJORITY))
	gt.Expect(imp.SubPolicy).To(Equal("Admins"))
}

func TestSetConsortiumChannelCreationPolicyFailures(t *testing.T) {
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

	tests := []struct {
		name           string
		consortiumName string
		updatedpolicy  Policy
		expectedErr    string
	}{
		{
			name:           "when policy is invalid",
			consortiumName: "Consortium1",
			updatedpolicy:  Policy{Type: ImplicitMetaPolicyType, Rule: "Bad Admins"},
			expectedErr:    "invalid implicit meta policy rule 'Bad Admins': unknown rule type 'Bad', expected ALL, ANY, or MAJORITY",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gt := NewGomegaWithT(t)
			err := c.Consortium(tt.consortiumName).SetChannelCreationPolicy(tt.updatedpolicy)
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}
