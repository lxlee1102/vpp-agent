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

//go:generate descriptor-adapter --descriptor-name Ikev2Profile --value-type *vpp_ikev2.Ikev2Profile --import "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2" --output-dir "descriptor"

package ikev2plugin

import (
	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/health/statuscheck"
	"go.ligato.io/cn-infra/v2/infra"
	"go.ligato.io/vpp-agent/v3/plugins/govppmux"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/descriptor"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls"

	_ "go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls/vpp2101"
)

type Ikev2Plugin struct {
	Deps
	// handler
	Ikev2Handler vppcalls.Ikev2VppAPI

	profileDescriptor *descriptor.Ikev2ProfileDescriptor
}

type Deps struct {
	infra.PluginDeps
	KVScheduler kvs.KVScheduler
	VPP         govppmux.API
	IfPlugin    ifplugin.API
	StatusCheck statuscheck.PluginStatusWriter // optional
}

func (p *Ikev2Plugin) Init() (err error) {
	if !p.VPP.IsPluginLoaded("ikev2") {
		p.Log.Warnf("VPP plugin ikev2 was disabled by VPP")
		return nil
	}

	// init Ikev2 handler
	p.Ikev2Handler = vppcalls.CompatibleIkev2VppHandler(p.VPP, p.IfPlugin.GetInterfaceIndex(), p.Log)
	if p.Ikev2Handler == nil {
		return errors.New("Ikev2 handler is not available")
	}

	p.profileDescriptor = descriptor.NewIkev2ProfileDescriptor(p.Ikev2Handler, p.Log)
	profileDescriptor := adapter.NewIkev2ProfileDescriptor(p.profileDescriptor.GetDescriptor())
	err = p.KVScheduler.RegisterKVDescriptor(profileDescriptor)
	if err != nil {
		return err
	}

	return nil
}

// AfterInit registers plugin with StatusCheck.
func (p *Ikev2Plugin) AfterInit() error {
	if p.StatusCheck != nil {
		p.StatusCheck.Register(p.PluginName, nil)
	}
	return nil
}
