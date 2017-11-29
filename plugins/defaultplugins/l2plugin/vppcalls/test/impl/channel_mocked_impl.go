// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package impl

import (
	"reflect"

	"unsafe"

	govppapi "git.fd.io/govpp.git/api"
)

//MockedChannel implements ChannelIntf for testing purposes
type MockedChannel struct {
	Channel govppapi.Channel

	//last message which passed through method SendRequest
	Msg govppapi.Message

	//list of all messages which passed through method SendRequest
	Msgs []govppapi.Message
}

//SendRequest just save input argument to structure field for future check
func (mockedChannel *MockedChannel) SendRequest(msg govppapi.Message) *govppapi.RequestCtx {
	mockedChannel.Msg = msg
	mockedChannel.Msgs = append(mockedChannel.Msgs, msg)
	mockedChannel.Channel.ReqChan <- &govppapi.VppRequest{
		Message: msg,
	}
	requestCtx := &govppapi.RequestCtx{}
	specifyChViaReflect(requestCtx, &mockedChannel.Channel)

	return requestCtx
}

func specifyChViaReflect(requestCtx *govppapi.RequestCtx, channel *govppapi.Channel) {
	rCh := reflect.ValueOf(&channel).Elem()

	rRequestCtx := reflect.ValueOf(requestCtx).Elem()
	rFieldCh := rRequestCtx.FieldByName("ch")
	rFieldCh = reflect.NewAt(rFieldCh.Type(), unsafe.Pointer(rFieldCh.UnsafeAddr())).Elem()

	rFieldCh.Set(rCh)
}
