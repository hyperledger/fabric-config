/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policydsl_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx/internal/policydsl"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"

	. "github.com/onsi/gomega"
)

func TestOutOf1(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OutOf(1, 'A.member', 'B.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(1, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1)}),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestOutOf2(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OutOf(2, 'A.member', 'B.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(2, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1)}),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestAnd(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("AND('A.member', 'B.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.And(policydsl.SignedBy(0), policydsl.SignedBy(1)),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestAndClientPeerOrderer(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("AND('A.client', 'B.peer')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_CLIENT, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_PEER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.And(policydsl.SignedBy(0), policydsl.SignedBy(1)),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestOr(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OR('A.member', 'B.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.Or(policydsl.SignedBy(0), policydsl.SignedBy(1)),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestComplex1(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OR('A.member', AND('B.member', 'C.member'))")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "C"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.Or(policydsl.SignedBy(2), policydsl.And(policydsl.SignedBy(0), policydsl.SignedBy(1))),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestComplex2(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OR(AND('A.member', 'B.member'), OR('C.admin', 'D.member'))")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_ADMIN, MspIdentifier: "C"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "D"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.Or(policydsl.And(policydsl.SignedBy(0), policydsl.SignedBy(1)), policydsl.Or(policydsl.SignedBy(2), policydsl.SignedBy(3))),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestMSPIDWIthSpecialChars(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OR('MSP.member', 'MSP.WITH.DOTS.member', 'MSP-WITH-DASHES.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "MSP"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "MSP.WITH.DOTS"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "MSP-WITH-DASHES"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(1, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1), policydsl.SignedBy(2)}),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestBadStringsNoPanic(t *testing.T) {
	gt := NewGomegaWithT(t)

	_, err := policydsl.FromString("OR('A.member', Bmember)") // error after 1st Evaluate()
	gt.Expect(err).To(MatchError("unrecognized token 'Bmember' in policy string"))

	_, err = policydsl.FromString("OR('A.member', 'Bmember')") // error after 2nd Evalute()
	gt.Expect(err).To(MatchError("unrecognized token 'Bmember' in policy string"))

	_, err = policydsl.FromString(`OR('A.member', '\'Bmember\'')`) // error after 3rd Evalute()
	gt.Expect(err).To(MatchError("unrecognized token 'Bmember' in policy string"))
}

func TestNodeOUs(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OR('A.peer', 'B.admin', 'C.orderer', 'D.client')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_PEER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_ADMIN, MspIdentifier: "B"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_ORDERER, MspIdentifier: "C"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_CLIENT, MspIdentifier: "D"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(1, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1), policydsl.SignedBy(2), policydsl.SignedBy(3)}),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestOutOfNumIsString(t *testing.T) {
	gt := NewGomegaWithT(t)

	p1, err := policydsl.FromString("OutOf('1', 'A.member', 'B.member')")
	gt.Expect(err).NotTo(HaveOccurred())

	principals := make([]*mb.MSPPrincipal, 0)

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})

	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})

	p2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(1, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1)}),
		Identities: principals,
	}

	gt.Expect(p1).To(Equal(p2))
}

func TestOutOfErrorCase(t *testing.T) {
	tests := []struct {
		testName     string
		policyString string
		expectedErr  string
	}{
		{
			testName:     "1st NewEvaluableExpressionWithFunctions() returns an error",
			policyString: "",
			expectedErr:  "Unexpected end of expression",
		},
		{
			testName:     "outof() if len(args)<2",
			policyString: "OutOf(1)",
			expectedErr:  "expected at least two arguments to NOutOf. Given 1",
		},
		{
			testName:     "outof() }else{. 1st arg is non of float, int, string",
			policyString: "OutOf(true, 'A.member')",
			expectedErr:  "unexpected type bool",
		},
		{
			testName:     "oufof() switch default. 2nd arg is not string.",
			policyString: "OutOf(1, 2)",
			expectedErr:  "unexpected type float64",
		},
		{
			testName:     "firstPass() switch default",
			policyString: "OutOf(1, 'true')",
			expectedErr:  "unexpected type bool",
		},
		{
			testName:     "secondPass() switch args[1].(type) default",
			policyString: `OutOf('\'\\\'A\\\'\'', 'B.member')`,
			expectedErr:  "unrecognized type, expected a number, got string",
		},
		{
			testName:     "secondPass() switch args[1].(type) default",
			policyString: `OutOf(1, '\'1\'')`,
			expectedErr:  "unrecognized type, expected a principal or a policy, got float64",
		},
		{
			testName:     "2nd NewEvaluateExpressionWithFunction() returns an error",
			policyString: `''`,
			expectedErr:  "Unexpected end of expression",
		},
		{
			testName:     "3rd NewEvaluateExpressionWithFunction() returns an error",
			policyString: `'\'\''`,
			expectedErr:  "Unexpected end of expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			gt := NewGomegaWithT(t)

			p, err := policydsl.FromString(tt.policyString)
			gt.Expect(p).To(BeNil())
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestBadStringBeforeFAB11404_ThisCanDeleteAfterFAB11404HasMerged(t *testing.T) {
	tests := []struct {
		testName     string
		policyString string
		expectedErr  string
	}{
		{
			testName:     "integer in string",
			policyString: "1",
			expectedErr:  `invalid policy string '1'`,
		},
		{
			testName:     "quoted integer in string",
			policyString: "'1'",
			expectedErr:  `invalid policy string ''1''`,
		},
		{
			testName:     "nested quoted integer in string",
			policyString: `'\'1\''`,
			expectedErr:  `invalid policy string ''\'1\'''`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			gt := NewGomegaWithT(t)

			p, err := policydsl.FromString(tt.policyString)
			gt.Expect(p).To(BeNil())
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestSecondPassBoundaryCheck(t *testing.T) {
	gt := NewGomegaWithT(t)

	// Check lower boundary
	// Prohibit t<0
	p0, err0 := policydsl.FromString("OutOf(-1, 'A.member', 'B.member')")
	gt.Expect(p0).To(BeNil())
	gt.Expect(err0).To(MatchError("invalid t-out-of-n predicate, t -1, n 2"))

	// Permit t==0 : always satisfied policy
	// There is no clear usecase of t=0, but somebody may already use it, so we don't treat as an error.
	p1, err1 := policydsl.FromString("OutOf(0, 'A.member', 'B.member')")
	gt.Expect(err1).NotTo(HaveOccurred())
	principals := make([]*mb.MSPPrincipal, 0)
	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "A"})})
	principals = append(principals, &mb.MSPPrincipal{
		PrincipalClassification: mb.MSPPrincipal_ROLE,
		Principal:               protoMarshalOrPanic(&mb.MSPRole{Role: mb.MSPRole_MEMBER, MspIdentifier: "B"})})
	expected1 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(0, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1)}),
		Identities: principals,
	}
	gt.Expect(p1).To(Equal(expected1))

	// Check upper boundary
	// Permit t==n+1 : never satisfied policy
	// Usecase: To create immutable ledger key
	p2, err2 := policydsl.FromString("OutOf(3, 'A.member', 'B.member')")
	gt.Expect(err2).NotTo(HaveOccurred())
	expected2 := &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policydsl.NOutOf(3, []*cb.SignaturePolicy{policydsl.SignedBy(0), policydsl.SignedBy(1)}),
		Identities: principals,
	}
	gt.Expect(p2).To(Equal(expected2))

	// Prohibit t>n + 1
	p3, err3 := policydsl.FromString("OutOf(4, 'A.member', 'B.member')")
	gt.Expect(p3).To(BeNil())
	gt.Expect(err3).To(MatchError("invalid t-out-of-n predicate, t 4, n 2"))
}

// protoMarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func protoMarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}

	return data
}
