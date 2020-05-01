/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonext

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"

	. "github.com/onsi/gomega"
)

func TestCommonProtolator(t *testing.T) {
	gt := NewGomegaWithT(t)

	// Envelope
	env := &Envelope{Envelope: &common.Envelope{}}
	gt.Expect(env.StaticallyOpaqueFields()).To(Equal([]string{"payload"}))
	msg, err := env.StaticallyOpaqueFieldProto("badproto")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("not a marshaled field: badproto"))
	msg, err = env.StaticallyOpaqueFieldProto("payload")
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(msg).To(Equal(&common.Payload{}))

	// Payload
	payload := &Payload{Payload: &common.Payload{}}
	gt.Expect(payload.VariablyOpaqueFields()).To(Equal([]string{"data"}))
	msg, err = payload.VariablyOpaqueFieldProto("badproto")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("not a marshaled field: badproto"))
	msg, err = payload.VariablyOpaqueFieldProto("data")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("cannot determine payload type when header is missing"))

	payload = &Payload{
		Payload: &common.Payload{
			Header: &common.Header{
				ChannelHeader: []byte("badbytes"),
			},
		},
	}
	msg, err = payload.VariablyOpaqueFieldProto("data")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("corrupt channel header: unexpected EOF"))

	ch := &common.ChannelHeader{
		Type: int32(common.HeaderType_CONFIG),
	}
	chbytes, _ := proto.Marshal(ch)
	payload = &Payload{
		Payload: &common.Payload{
			Header: &common.Header{
				ChannelHeader: chbytes,
			},
		},
	}
	msg, err = payload.VariablyOpaqueFieldProto("data")
	gt.Expect(msg).To(Equal(&common.ConfigEnvelope{}))
	gt.Expect(err).NotTo(HaveOccurred())

	ch = &common.ChannelHeader{
		Type: int32(common.HeaderType_CONFIG_UPDATE),
	}
	chbytes, _ = proto.Marshal(ch)
	payload = &Payload{
		Payload: &common.Payload{
			Header: &common.Header{
				ChannelHeader: chbytes,
			},
		},
	}
	msg, err = payload.VariablyOpaqueFieldProto("data")
	gt.Expect(msg).To(Equal(&common.ConfigUpdateEnvelope{}))
	gt.Expect(err).NotTo(HaveOccurred())

	ch = &common.ChannelHeader{
		Type: int32(common.HeaderType_CHAINCODE_PACKAGE),
	}
	chbytes, _ = proto.Marshal(ch)
	payload = &Payload{
		Payload: &common.Payload{
			Header: &common.Header{
				ChannelHeader: chbytes,
			},
		},
	}
	msg, err = payload.VariablyOpaqueFieldProto("data")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("decoding type 6 is unimplemented"))

	// Header
	var header *Header
	gt.Expect(header.StaticallyOpaqueFields()).To(Equal(
		[]string{"channel_header", "signature_header"}))

	msg, err = header.StaticallyOpaqueFieldProto("badproto")
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("unknown header field: badproto"))

	msg, err = header.StaticallyOpaqueFieldProto("channel_header")
	gt.Expect(msg).To(Equal(&common.ChannelHeader{}))
	gt.Expect(err).NotTo(HaveOccurred())

	msg, err = header.StaticallyOpaqueFieldProto("signature_header")
	gt.Expect(msg).To(Equal(&common.SignatureHeader{}))
	gt.Expect(err).NotTo(HaveOccurred())

	// BlockData
	var bd *BlockData
	gt.Expect(bd.StaticallyOpaqueSliceFields()).To(Equal([]string{"data"}))

	msg, err = bd.StaticallyOpaqueSliceFieldProto("badslice", 0)
	gt.Expect(msg).To(BeNil())
	gt.Expect(err).To(MatchError("not an opaque slice field: badslice"))
	msg, err = bd.StaticallyOpaqueSliceFieldProto("data", 0)
	gt.Expect(msg).To(Equal(&common.Envelope{}))
	gt.Expect(err).NotTo(HaveOccurred())
}
