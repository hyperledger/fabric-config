/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protolator

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/protolator/testprotos"

	. "github.com/onsi/gomega"
)

func extractSimpleMsgPlainField(source []byte) string {
	result := &testprotos.SimpleMsg{}
	err := proto.Unmarshal(source, result)
	if err != nil {
		panic(err)
	}
	return result.PlainField
}

func TestPlainStaticallyOpaqueMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.StaticallyOpaqueMsg{
		PlainOpaqueField: protoMarshalOrPanic(&testprotos.SimpleMsg{
			PlainField: pfValue,
		}),
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.StaticallyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.PlainOpaqueField)).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.PlainOpaqueField)))

	fieldFactories = []protoFieldFactory{tppff, staticallyOpaqueFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.PlainOpaqueField)).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.PlainOpaqueField)))
}

func TestMapStaticallyOpaqueMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	mapKey := "bar"
	startMsg := &testprotos.StaticallyOpaqueMsg{
		MapOpaqueField: map[string][]byte{
			mapKey: protoMarshalOrPanic(&testprotos.SimpleMsg{
				PlainField: pfValue,
			}),
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.StaticallyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.MapOpaqueField[mapKey])).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.MapOpaqueField[mapKey])))

	fieldFactories = []protoFieldFactory{tppff, staticallyOpaqueMapFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.MapOpaqueField[mapKey])).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.MapOpaqueField[mapKey])))
}

func TestSliceStaticallyOpaqueMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.StaticallyOpaqueMsg{
		SliceOpaqueField: [][]byte{
			protoMarshalOrPanic(&testprotos.SimpleMsg{
				PlainField: pfValue,
			}),
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.StaticallyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.SliceOpaqueField[0])).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.SliceOpaqueField[0])))

	fieldFactories = []protoFieldFactory{tppff, staticallyOpaqueSliceFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.SliceOpaqueField[0])).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.SliceOpaqueField[0])))
}

func TestIgnoredNilFields(t *testing.T) {
	gt := NewGomegaWithT(t)

	_ = StaticallyOpaqueFieldProto(&testprotos.UnmarshalableDeepFields{})
	_ = StaticallyOpaqueMapFieldProto(&testprotos.UnmarshalableDeepFields{})
	_ = StaticallyOpaqueSliceFieldProto(&testprotos.UnmarshalableDeepFields{})

	fieldFactories = []protoFieldFactory{
		staticallyOpaqueFieldFactory{},
		staticallyOpaqueMapFieldFactory{},
		staticallyOpaqueSliceFieldFactory{},
	}

	err := DeepMarshalJSON(&bytes.Buffer{}, &testprotos.UnmarshalableDeepFields{
		PlainOpaqueField: []byte("fake"),
	})
	gt.Expect(err).To(MatchError("*testprotos.UnmarshalableDeepFields: error in PopulateTo for field plain_opaque_field for message *testprotos.UnmarshalableDeepFields: intentional error"))
	err = DeepMarshalJSON(&bytes.Buffer{}, &testprotos.UnmarshalableDeepFields{
		MapOpaqueField: map[string][]byte{"foo": []byte("bar")},
	})
	gt.Expect(err).To(MatchError("*testprotos.UnmarshalableDeepFields: error in PopulateTo for map field map_opaque_field and key foo for message *testprotos.UnmarshalableDeepFields: intentional error"))
	err = DeepMarshalJSON(&bytes.Buffer{}, &testprotos.UnmarshalableDeepFields{
		SliceOpaqueField: [][]byte{[]byte("bar")},
	})
	gt.Expect(err).To(MatchError("*testprotos.UnmarshalableDeepFields: error in PopulateTo for slice field slice_opaque_field at index 0 for message *testprotos.UnmarshalableDeepFields: intentional error"))
	err = DeepMarshalJSON(&bytes.Buffer{}, &testprotos.UnmarshalableDeepFields{})
	gt.Expect(err).NotTo(HaveOccurred())
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
