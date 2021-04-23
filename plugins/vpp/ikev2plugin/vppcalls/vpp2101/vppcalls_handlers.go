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
	govppapi "git.fd.io/govpp.git/api"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101"
	vpp_ikev2 "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101/ikev2"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls"
)

func init() {
	var msgs []govppapi.Message
	msgs = append(msgs, vpp_ikev2.AllMessages()...)

	vppcalls.AddHandlerVersion(vpp2101.Version, msgs, NewIkev2VppHandler)
}

type Ikev2VppHandler struct {
	callsChannel govppapi.Channel
	ifIndexes    ifaceidx.IfaceMetadataIndex
	log          logging.Logger
}

func NewIkev2VppHandler(ch govppapi.Channel, ifIdx ifaceidx.IfaceMetadataIndex, log logging.Logger) vppcalls.Ikev2VppAPI {
	return &Ikev2VppHandler{ch, ifIdx, log}
}
