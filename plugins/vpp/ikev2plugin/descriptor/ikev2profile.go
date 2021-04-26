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
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	vpp_ifdescriptor "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/descriptor"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls"
	ike "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"
)

const (
	// ProfileDescriptorName is the name of the descriptor for VPP ikev2 profile.
	ProfileDescriptorName = "vpp-ikev2-profile"

	// Length of wireguard public-key in base64. It should be equal 32 in binary
	PeerKeyLen = 44

	// MaxU16
	MaxU16 = 0xFFFF

	// dependency labels
	//wgPeerVrfTableDep = "vrf-table-exists"
)

// A list of errors:
var (
	// ErrWgPeerKeyLen is returned when public-key length has wrong size.
	ErrWgPeerKeyLen = errors.New("Invalid wireguard peer public-key length")

	// ErrWgPeerWithoutInterface is returned when wireguard interface name is empty.
	ErrWgPeerWithoutInterface = errors.New("Wireguard interface is not defined")

	// ErrWgPeerPKeepalive is returned when persistent keepalive exceeds max value.
	ErrWgPeerPKeepalive = errors.New("Persistent keepalive exceeds the limits")

	// ErrWgPeerPort is returned when udp-port exceeds max value.
	ErrWgPeerPort = errors.New("Invalid wireguard peer port")

	// ErrWgPeerEndpointMissing is returned when endpoint address was not set or set to an empty string.
	ErrWgPeerEndpointMissing = errors.Errorf("Missing endpoint address for wireguard peer")

	// ErrWgSrcAddrBad is returned when endpoint address was not set to valid IP address.
	ErrWgPeerEndpointBad = errors.New("Invalid wireguard peer endpoint")

	// ErrWgPeerAllowedIPs is returned when one of allowedIp address was not set to valid IP address.
	ErrWgPeerAllowedIPs = errors.New("Invalid wireguard peer allowedIps")
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
		WithMetadata:         true,
	}
}

func (d *Ikev2ProfileDescriptor) EquivalentIkev2Profile(key string, oldProfile, newProfile *ike.Ikev2Profile) bool {
	// compare base fields
	return proto.Equal(oldProfile, newProfile)
}

func (d *Ikev2ProfileDescriptor) Validate(key string, profile *ike.Ikev2Profile) (err error) {
	//	if len(peer.PublicKey) != PeerKeyLen {
	//		return kvs.NewInvalidValueError(ErrWgPeerKeyLen, "public_key")
	//	}
	//	if peer.WgIfName == "" {
	//		return kvs.NewInvalidValueError(ErrWgPeerWithoutInterface, "wg_if_name")
	//	}
	//	if peer.PersistentKeepalive > MaxU16 {
	//		return kvs.NewInvalidValueError(ErrWgPeerPKeepalive, "persistent_keepalive")
	//	}
	//	if peer.Endpoint == "" {
	//		return kvs.NewInvalidValueError(ErrWgPeerEndpointMissing, "endpoint")
	//	}
	//	if net.ParseIP(peer.Endpoint).IsUnspecified() {
	//		return kvs.NewInvalidValueError(ErrWgPeerEndpointBad, "endpoint")
	//	}
	//	if peer.Port > MaxU16 {
	//		return kvs.NewInvalidValueError(ErrWgPeerPort, "port")
	//	}
	//
	//	for _, allowedIp := range peer.AllowedIps {
	//		_,err := ip_types.ParsePrefix(allowedIp)
	//		if err != nil {
	//			return kvs.NewInvalidValueError(ErrWgPeerAllowedIPs, "allowed_ips")
	//		}
	//	}
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

// Retrieve returns all wg peers.
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
