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

func extractNestedMsgPlainField(source []byte) string {
	result := &testprotos.NestedMsg{}
	err := proto.Unmarshal(source, result)
	if err != nil {
		panic(err)
	}
	return result.PlainNestedField.PlainField
}

func TestPlainVariablyOpaqueMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.VariablyOpaqueMsg{
		OpaqueType: "NestedMsg",
		PlainOpaqueField: protoMarshalOrPanic(&testprotos.NestedMsg{
			PlainNestedField: &testprotos.SimpleMsg{
				PlainField: pfValue,
			},
		}),
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.VariablyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.PlainOpaqueField)).NotTo(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.PlainOpaqueField)))

	fieldFactories = []protoFieldFactory{tppff, nestedFieldFactory{}, variablyOpaqueFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.PlainOpaqueField)).To(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.PlainOpaqueField)))
}

func TestMapVariablyOpaqueMsg(t *testing.T) {
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
	startMsg := &testprotos.VariablyOpaqueMsg{
		OpaqueType: "NestedMsg",
		MapOpaqueField: map[string][]byte{
			mapKey: protoMarshalOrPanic(&testprotos.NestedMsg{
				PlainNestedField: &testprotos.SimpleMsg{
					PlainField: pfValue,
				},
			}),
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.VariablyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.MapOpaqueField[mapKey])).NotTo(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.MapOpaqueField[mapKey])))

	fieldFactories = []protoFieldFactory{tppff, nestedFieldFactory{}, variablyOpaqueMapFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.MapOpaqueField[mapKey])).To(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.MapOpaqueField[mapKey])))
}

func TestSliceVariablyOpaqueMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.VariablyOpaqueMsg{
		OpaqueType: "NestedMsg",
		SliceOpaqueField: [][]byte{
			protoMarshalOrPanic(&testprotos.NestedMsg{
				PlainNestedField: &testprotos.SimpleMsg{
					PlainField: pfValue,
				},
			}),
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.VariablyOpaqueMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.SliceOpaqueField[0])).NotTo(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.SliceOpaqueField[0])))

	fieldFactories = []protoFieldFactory{tppff, nestedFieldFactory{}, variablyOpaqueSliceFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractNestedMsgPlainField(newMsg.SliceOpaqueField[0])).To(Equal(fromPrefix + toPrefix + extractNestedMsgPlainField(startMsg.SliceOpaqueField[0])))
}
