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

package vppcalls

import (
	govppapi "git.fd.io/govpp.git/api"
	"go.ligato.io/cn-infra/v2/logging"
	ik "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"

	"go.ligato.io/vpp-agent/v3/plugins/vpp"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
)

type Ikev2VppAPI interface {
	Ikev2VppRead

	// Set profile via binary API
	AddProfile(prof *ik.Ikev2Profile) error
	// Remove profile via binary API
	RemoveProfile(profile_id string) error
}

// Ikev2VPPRead provides read methods for ikev2
type Ikev2VppRead interface {
	// DumpWgPeer returns a peers state
	DumpIkev2Profile() (profList []*ik.Ikev2Profile, err error)
}

var Handler = vpp.RegisterHandler(vpp.HandlerDesc{
	Name:       "ikev2",
	HandlerAPI: (*Ikev2VppAPI)(nil),
})

type NewHandlerFunc func(ch govppapi.Channel, ifDdx ifaceidx.IfaceMetadataIndex, log logging.Logger) Ikev2VppAPI

func AddHandlerVersion(version vpp.Version, msgs []govppapi.Message, h NewHandlerFunc) {
	Handler.AddVersion(vpp.HandlerVersion{
		Version: version,
		Check: func(c vpp.Client) error {
			ch, err := c.NewAPIChannel()
			if err != nil {
				return err
			}
			return ch.CheckCompatiblity(msgs...)
		},
		NewHandler: func(c vpp.Client, a ...interface{}) vpp.HandlerAPI {
			ch, err := c.NewAPIChannel()
			if err != nil {
				return err
			}
			return h(ch, a[0].(ifaceidx.IfaceMetadataIndex), a[1].(logging.Logger))
		},
	})
}

func CompatibleIkev2VppHandler(c vpp.Client, ifIdx ifaceidx.IfaceMetadataIndex, log logging.Logger) Ikev2VppAPI {
	if v := Handler.FindCompatibleVersion(c); v != nil {
		return v.NewHandler(c, ifIdx, log).(Ikev2VppAPI)
	}
	return nil
}
