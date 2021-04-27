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

package descriptor

import (
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	vpp_ifdescriptor "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/descriptor"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls"
	ike "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"
	interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
)

const (
	// ProfileDescriptorName is the name of the descriptor for VPP ikev2 profile.
	ProfileDescriptorName = "vpp-ikev2-profile"

	// MaxU16
	MaxU16 = 0xFFFF

	// MaxU32
	MaxU32 = 0xFFFFFFFF

	// dependency labels
	tunnelIfDep    = "tunnel-if-exists"
	responderIfDep = "responder-if-exists"
	AddressDep     = "ip-address-exists"
)

// A list of errors:
var (
	ErrIkev2ProfileName = errors.New("Invalid ikev2 profile name (or id)")

	ErrIkev2ProfileAuth = errors.New("Invalid ikev2 profile Auth informations")

	ErrIkev2ProfileTunIF = errors.New("Ikev2 tunnel interface is not defined")

	ErrIkev2ProfileLocID = errors.New("Lost or Invalid ikev2 local id")

	ErrIkev2ProfileRemID = errors.New("Lost or Invalid ikev2 remote id")

	ErrIkev2ProfileMoreID = errors.New("Too more ikev2 profile local/remote id")

	ErrIkev2ProfileRespAddr = errors.New("Lost or Invalid ikev2 repsonder's address")

	ErrIkev2ProfileLocTS = errors.New("Lost or Invalid ikev2 local traffic_selector")

	ErrIkev2ProfileRemTS = errors.New("Lost or Invalid ikev2 remote traffic_selector")

	ErrIkev2ProfileTSPort = errors.New("Invalid ikev2 traffic_selector port")

	ErrIkev2ProfileTSAddr = errors.New("Invalid ikev2 traffic_selector address")

	ErrIkev2ProfileTSProto = errors.New("Invalid ikev2 traffic_selector protocol, 0-3 is valid")

	ErrIkev2ProfileTSMore = errors.New("Invalid ikev2 profile, only support 2 traffic_selector, local/remote")

	ErrIkev2ProfileLifeTime = errors.New("Ikev2 lifetime exceeds the limits")

	ErrIkev2ProfileLifeTimeJitter = errors.New("Ikev2 life time jitter exceeds the limits")

	ErrIkev2ProfileHandover = errors.New("Invalid ikev2 handover")

	ErrIkev2IpsecOverUdpPort = errors.New("Invalid ipsec over udp port")

	ErrIkev2ProfileIkeTSCyptorAlg = errors.New("Invalid ike transforms crypto algorithm")

	ErrIkev2ProfileIkeTSCyptorKeySize = errors.New("Invalid ike transforms key size")

	ErrIkev2ProfileIkeTSIntegAlg = errors.New("Invalid ike transforms integ algorithm")

	ErrIkev2ProfileIkeTSDhType = errors.New("Invalid ike transforms DH type")

	ErrIkev2ProfileEspTSCyptorAlg = errors.New("Invalid esp transforms crypto algorithm")

	ErrIkev2ProfileEspTSCyptorKeySize = errors.New("Invalid esp transforms key size")

	ErrIkev2ProfileEspTSIntegAlg = errors.New("Invalid esp transforms integ algorithm")
)

// Ikev2ProfileDescriptor teaches KVScheduler how to configure VPP Ikev2.
type Ikev2ProfileDescriptor struct {
	log          logging.Logger
	ikev2Handler vppcalls.Ikev2VppAPI
}

// NewIkev2ProfileDescriptor creates a new instance of the Ikev2 Profile descriptor.
func NewIkev2ProfileDescriptor(ikev2Handler vppcalls.Ikev2VppAPI, log logging.PluginLogger) *Ikev2ProfileDescriptor {
	return &Ikev2ProfileDescriptor{
		ikev2Handler: ikev2Handler,
		log:          log.NewLogger("ikev2-profile-descriptor"),
	}
}

// GetDescriptor returns descriptor suitable for registration (via adapter) with
// the KVScheduler.
func (d *Ikev2ProfileDescriptor) GetDescriptor() *adapter.Ikev2ProfileDescriptor {
	return &adapter.Ikev2ProfileDescriptor{
		Name:                 ProfileDescriptorName,
		NBKeyPrefix:          ike.ModelIkev2Profile.KeyPrefix(),
		ValueTypeName:        ike.ModelIkev2Profile.ProtoName(),
		KeySelector:          ike.ModelIkev2Profile.IsKeyValid,
		KeyLabel:             ike.ModelIkev2Profile.StripKeyPrefix,
		ValueComparator:      d.EquivalentIkev2Profile,
		Validate:             d.Validate,
		Create:               d.Create,
		Delete:               d.Delete,
		Retrieve:             d.Retrieve,
		RetrieveDependencies: []string{vpp_ifdescriptor.InterfaceDescriptorName},
		Dependencies:         d.Dependencies,
		WithMetadata:         true,
	}
}

func (d *Ikev2ProfileDescriptor) EquivalentIkev2Profile(key string, oldProfile, newProfile *ike.Ikev2Profile) bool {
	// compare base fields
	return proto.Equal(oldProfile, newProfile)
}

func (d *Ikev2ProfileDescriptor) Validate(key string, pfile *ike.Ikev2Profile) (err error) {
	if len(pfile.Name) == 0 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileName, "name")
	}

	if pfile.Auth == nil || len(pfile.Auth.Data) <= 0 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileAuth, "auth")
	}

	if pfile.Id == nil || len(pfile.Id) == 0 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileLocID, "id")
	}
	idlen := len(pfile.Id)
	if idlen == 1 {
		if pfile.Id[0].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileRemID, "id")
		} else {
			return kvs.NewInvalidValueError(ErrIkev2ProfileLocID, "id")
		}
	} else if idlen == 2 {
		if pfile.Id[0].IsLocal && pfile.Id[1].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileRemID, "id")
		}
		if !pfile.Id[0].IsLocal && !pfile.Id[1].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileLocID, "id")
		}
	} else {
		return kvs.NewInvalidValueError(ErrIkev2ProfileMoreID, "id")
	}

	if pfile.Responder != nil {
		if pfile.Responder.Addr != "" {
			if net.ParseIP(pfile.Responder.Addr) == nil {
				return kvs.NewInvalidValueError(ErrIkev2ProfileRespAddr, "responder")
			}
		}
	}

	if pfile.TrafficSelector == nil || len(pfile.TrafficSelector) == 0 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileLocTS, "traffic_seclector")
	}
	err = validateTrafficSelector(pfile.TrafficSelector)
	if err != nil {
		return err
	}

	err = validateIkeTransforms(pfile.IkeTransforms)
	if err != nil {
		return err
	}

	err = validateEspTransforms(pfile.EspTransforms)
	if err != nil {
		return err
	}

	if pfile.LifeTimeJitter > MaxU32 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileLifeTimeJitter, "life_time_jitter")
	}

	if pfile.LifeTime > pfile.LifeTimeMaxdata {
		return kvs.NewInvalidValueError(ErrIkev2ProfileLifeTime, "life_time")
	}

	if pfile.Handover > MaxU32 {
		return kvs.NewInvalidValueError(ErrIkev2ProfileHandover, "handover")
	}

	if pfile.IpsecOverUdpport > MaxU16 {
		return kvs.NewInvalidValueError(ErrIkev2IpsecOverUdpPort, "ipsec_over_updport")
	}

	if pfile.TunnelInterface == "" {
		return kvs.NewInvalidValueError(ErrIkev2ProfileTunIF, "tunnel_interface")
	}

	return nil
}

func validateTrafficSelector(ts []*ike.Ikev2Profile_TrafficSelector) error {
	tslen := len(ts)
	if tslen == 1 {
		if ts[0].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileRemTS, "traffic_seclector")
		} else {
			return kvs.NewInvalidValueError(ErrIkev2ProfileLocTS, "traffic_seclector")
		}
	} else if tslen == 2 {
		if ts[0].IsLocal && ts[1].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileRemTS, "traffic_seclector")
		} else if !ts[0].IsLocal && !ts[1].IsLocal {
			return kvs.NewInvalidValueError(ErrIkev2ProfileLocTS, "traffic_seclector")
		}

		for _, v := range ts {
			if v.StartPort > MaxU16 || v.EndPort > MaxU16 {
				return kvs.NewInvalidValueError(ErrIkev2ProfileTSPort, "traffic_seclector")
			}
			if net.ParseIP(v.StartAddr) == nil || net.ParseIP(v.EndAddr) == nil {
				return kvs.NewInvalidValueError(ErrIkev2ProfileTSAddr, "traffic_seclector")
			}
			_, ok := ike.Ikev2Proto_name[int32(v.Protocol)]
			if !ok {
				return kvs.NewInvalidValueError(ErrIkev2ProfileTSProto, "traffic_seclector")
			}
		}
	} else {
		return kvs.NewInvalidValueError(ErrIkev2ProfileTSMore, "traffic_seclector")
	}

	return nil
}

func validateIkeTransforms(tf *ike.Ikev2Profile_IkeTransforms) error {
	if tf == nil {
		return nil
	}

	_, ok := ike.CryptoAlg_name[int32(tf.CryptoAlg)]
	if !ok {
		return kvs.NewInvalidValueError(ErrIkev2ProfileIkeTSCyptorAlg, "ike_transforms")
	}

	_, ok = ike.IntegAlg_name[int32(tf.IntegAlg)]
	if !ok {
		return kvs.NewInvalidValueError(ErrIkev2ProfileIkeTSIntegAlg, "ike_transforms")
	}

	_, ok = ike.DHType_name[int32(tf.DhType)]
	if !ok {
		return kvs.NewInvalidValueError(ErrIkev2ProfileIkeTSDhType, "ike_transforms")
	}

	return nil
}

func validateEspTransforms(tf *ike.Ikev2Profile_EspTransforms) error {
	if tf == nil {
		return nil
	}

	_, ok := ike.CryptoAlg_name[int32(tf.CryptoAlg)]
	if !ok {
		return kvs.NewInvalidValueError(ErrIkev2ProfileIkeTSCyptorAlg, "esp_transforms")
	}

	_, ok = ike.IntegAlg_name[int32(tf.IntegAlg)]
	if !ok {
		return kvs.NewInvalidValueError(ErrIkev2ProfileIkeTSIntegAlg, "esp_transforms")
	}

	return nil
}

// Create adds a new ikev2 profile.
func (d *Ikev2ProfileDescriptor) Create(key string, profile *ike.Ikev2Profile) (metadata interface{}, err error) {
	err = d.ikev2Handler.AddProfile(profile)
	if err != nil {
		d.log.Error(err)
	}

	return metadata, err
}

// Delete removes VPP ikev2 profile.
func (d *Ikev2ProfileDescriptor) Delete(key string, profile *ike.Ikev2Profile, metadata interface{}) error {
	err := d.ikev2Handler.RemoveProfile(profile.Name)
	if err != nil {
		d.log.Error(err)
	}
	return err
}

// Retrieve returns all ikev2 profile
func (d *Ikev2ProfileDescriptor) Retrieve(correlate []adapter.Ikev2ProfileKVWithMetadata) (dump []adapter.Ikev2ProfileKVWithMetadata, err error) {
	// dump Ikev2 Profile
	prs, err := d.ikev2Handler.DumpIkev2Profile()
	if err != nil {
		d.log.Error(err)
		return dump, err
	}
	for _, pr := range prs {
		dump = append(dump, adapter.Ikev2ProfileKVWithMetadata{
			Key:    models.Key(pr),
			Value:  pr,
			Origin: kvs.FromNB,
		})
	}

	return dump, nil
}

// Dependencies lists the interface and SAs as the dependencies for the binding.
func (d *Ikev2ProfileDescriptor) Dependencies(key string, value *ike.Ikev2Profile) []kvs.Dependency {
	deps := []kvs.Dependency{
		{
			Label: tunnelIfDep,
			Key:   interfaces.InterfaceKey(value.TunnelInterface),
		},
	}

	if value.Responder != nil {
		if value.Responder.Interface != "" {
			deps = append(deps, kvs.Dependency{
				Label: responderIfDep,
				Key:   interfaces.InterfaceKey(value.Responder.Interface),
			})
		}
		// TODO : checking value.Responder.Addr , how to do ?
	}

	return deps
}
