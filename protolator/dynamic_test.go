/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protolator

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-config/protolator/testprotos"

	. "github.com/onsi/gomega"
)

func TestPlainDynamicMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}}

	pfValue := "foo"
	startMsg := &testprotos.DynamicMsg{
		DynamicType: "SimpleMsg",
		PlainDynamicField: &testprotos.ContextlessMsg{
			OpaqueField: protoMarshalOrPanic(&testprotos.SimpleMsg{
				PlainField: pfValue,
			}),
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.DynamicMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.PlainDynamicField.OpaqueField)).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.PlainDynamicField.OpaqueField)))

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}, dynamicFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.PlainDynamicField.OpaqueField)).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.PlainDynamicField.OpaqueField)))
}

func TestMapDynamicMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}}

	pfValue := "foo"
	mapKey := "bar"
	startMsg := &testprotos.DynamicMsg{
		DynamicType: "SimpleMsg",
		MapDynamicField: map[string]*testprotos.ContextlessMsg{
			mapKey: {
				OpaqueField: protoMarshalOrPanic(&testprotos.SimpleMsg{
					PlainField: pfValue,
				}),
			},
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.DynamicMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.MapDynamicField[mapKey].OpaqueField)).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.MapDynamicField[mapKey].OpaqueField)))

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}, dynamicMapFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.MapDynamicField[mapKey].OpaqueField)).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.MapDynamicField[mapKey].OpaqueField)))
}

func TestSliceDynamicMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}}

	pfValue := "foo"
	startMsg := &testprotos.DynamicMsg{
		DynamicType: "SimpleMsg",
		SliceDynamicField: []*testprotos.ContextlessMsg{
			{
				OpaqueField: protoMarshalOrPanic(&testprotos.SimpleMsg{
					PlainField: pfValue,
				}),
			},
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.DynamicMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.SliceDynamicField[0].OpaqueField)).NotTo(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.SliceDynamicField[0].OpaqueField)))

	fieldFactories = []protoFieldFactory{tppff, variablyOpaqueFieldFactory{}, dynamicSliceFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(extractSimpleMsgPlainField(newMsg.SliceDynamicField[0].OpaqueField)).To(Equal(fromPrefix + toPrefix + extractSimpleMsgPlainField(startMsg.SliceDynamicField[0].OpaqueField)))
}
