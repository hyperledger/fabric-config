/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protolator

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-config/protolator/testprotos"

	. "github.com/onsi/gomega"
)

func TestPlainNestedMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.NestedMsg{
		PlainNestedField: &testprotos.SimpleMsg{
			PlainField: pfValue,
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.NestedMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.PlainNestedField.PlainField).NotTo(Equal(fromPrefix + toPrefix + startMsg.PlainNestedField.PlainField))

	fieldFactories = []protoFieldFactory{tppff, nestedFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.PlainNestedField.PlainField).To(Equal(fromPrefix + toPrefix + startMsg.PlainNestedField.PlainField))
}

func TestMapNestedMsg(t *testing.T) {
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
	startMsg := &testprotos.NestedMsg{
		MapNestedField: map[string]*testprotos.SimpleMsg{
			mapKey: {
				PlainField: pfValue,
			},
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.NestedMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.MapNestedField[mapKey].PlainField).NotTo(Equal(fromPrefix + toPrefix + startMsg.MapNestedField[mapKey].PlainField))

	fieldFactories = []protoFieldFactory{tppff, nestedMapFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.MapNestedField[mapKey].PlainField).To(Equal(fromPrefix + toPrefix + startMsg.MapNestedField[mapKey].PlainField))
}

func TestSliceNestedMsg(t *testing.T) {
	gt := NewGomegaWithT(t)

	fromPrefix := "from"
	toPrefix := "to"
	tppff := &testProtoPlainFieldFactory{
		fromPrefix: fromPrefix,
		toPrefix:   toPrefix,
	}

	fieldFactories = []protoFieldFactory{tppff}

	pfValue := "foo"
	startMsg := &testprotos.NestedMsg{
		SliceNestedField: []*testprotos.SimpleMsg{
			{
				PlainField: pfValue,
			},
		},
	}

	var buffer bytes.Buffer
	err := DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	newMsg := &testprotos.NestedMsg{}
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.SliceNestedField[0].PlainField).NotTo(Equal(fromPrefix + toPrefix + startMsg.SliceNestedField[0].PlainField))

	fieldFactories = []protoFieldFactory{tppff, nestedSliceFieldFactory{}}

	buffer.Reset()
	err = DeepMarshalJSON(&buffer, startMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	err = DeepUnmarshalJSON(bytes.NewReader(buffer.Bytes()), newMsg)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(newMsg.SliceNestedField[0].PlainField).To(Equal(fromPrefix + toPrefix + startMsg.SliceNestedField[0].PlainField))
}
