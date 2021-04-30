//  Copyright (c) 2020 Doc.ai and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vpp2101

import (
	vpp_ikev2 "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101/ikev2"
	ikev2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"
)

// DumpIkev2Profile implements ikev2 handler.
func (h *Ikev2VppHandler) DumpIkev2Profile() (profList []*ikev2.Ikev2Profile, err error) {
	req := &vpp_ikev2.Ikev2ProfileDump{}
	requestCtx := h.callsChannel.SendMultiRequest(req)

	var vppProfileList []*vpp_ikev2.Ikev2ProfileDetails
	for {
		vppProfileDetails := &vpp_ikev2.Ikev2ProfileDetails{}
		stop, err := requestCtx.ReceiveReply(vppProfileDetails)
		if stop {
			break
		}
		if err != nil {
			return nil, err
		}
		vppProfileList = append(vppProfileList, vppProfileDetails)
	}

	for _, vppProfileDetails := range vppProfileList {
		profDetails := &ikev2.Ikev2Profile{
			Name: vppProfileDetails.Profile.Name,
			// TODO others
		}

		profList = append(profList, profDetails)
	}

	return
}
