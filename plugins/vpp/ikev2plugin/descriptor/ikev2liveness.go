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
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ikev2plugin/vppcalls"
	ike "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"
)

const (
	// LivenessDescriptorName is the name of the descriptor for VPP ikev2 liveness.
	LivenessDescriptorName = "vpp-ikev2-liveness"

	// DefaultLivenessRetries  is default value of ikev2vpn reties
	DefaultLivenessRetries = 3

	// DefaultLivenessPeriodCheck is default value of ikev2vpn checking period
	DefaultLivenessPeriodCheck = 30
)

// A list of errors:
// var ()
var (
	ErrIkev2Liveness = errors.New("Invalid ikve2 liveness args, must > 0")
)

// Ikev2LivenessDescriptor teaches KVScheduler how to configure VPP Ikev2.
type Ikev2LivenessDescriptor struct {
	log          logging.Logger
	ikev2Handler vppcalls.Ikev2VppAPI
}

// NewIkev2LivenessDescriptor creates a new instance of the Ikev2 Liveness descriptor.
func NewIkev2LivenessDescriptor(ikev2Handler vppcalls.Ikev2VppAPI, log logging.PluginLogger) *Ikev2LivenessDescriptor {
	return &Ikev2LivenessDescriptor{
		ikev2Handler: ikev2Handler,
		log:          log.NewLogger("ikev2-liveness-descriptor"),
	}
}

// GetDescriptor returns descriptor suitable for registration (via adapter) with
// the KVScheduler.
func (d *Ikev2LivenessDescriptor) GetDescriptor() *adapter.Ikev2LivenessDescriptor {
	return &adapter.Ikev2LivenessDescriptor{
		Name:            LivenessDescriptorName,
		NBKeyPrefix:     ike.ModelIkev2Liveness.KeyPrefix(),
		ValueTypeName:   ike.ModelIkev2Liveness.ProtoName(),
		KeySelector:     ike.ModelIkev2Liveness.IsKeyValid,
		KeyLabel:        ike.ModelIkev2Liveness.StripKeyPrefix,
		ValueComparator: d.EquivalentIkev2Liveness,
		Validate:        d.Validate,
		Create:          d.Create,
		Delete:          d.Delete,
		Retrieve:        d.Retrieve,
		WithMetadata:    true,
	}
}

func (d *Ikev2LivenessDescriptor) EquivalentIkev2Liveness(key string, oldLiveness, newLiveness *ike.Ikev2Liveness) bool {
	// compare base fields
	return proto.Equal(oldLiveness, newLiveness)
}

func (d *Ikev2LivenessDescriptor) Validate(key string, pfile *ike.Ikev2Liveness) (err error) {
	if pfile.Period <= 0 || pfile.MaxRetries <= 0 {
		return kvs.NewInvalidValueError(ErrIkev2Liveness, "liveness")
	}
	return nil
}

// Create adds a new ikev2 liveness.
func (d *Ikev2LivenessDescriptor) Create(key string, liveness *ike.Ikev2Liveness) (metadata interface{}, err error) {
	err = d.ikev2Handler.SetLiveness(liveness)
	if err != nil {
		d.log.Error(err)
	}

	return metadata, err
}

// Delete removes VPP ikev2 liveness.
func (d *Ikev2LivenessDescriptor) Delete(key string, liveness *ike.Ikev2Liveness, metadata interface{}) error {
	DefLiveness := &ike.Ikev2Liveness{
		Period:     DefaultLivenessPeriodCheck,
		MaxRetries: DefaultLivenessRetries,
	}

	err := d.ikev2Handler.SetLiveness(DefLiveness)
	if err != nil {
		d.log.Error(err)
	}
	return err
}

// Retrieve returns all ikev2 liveness
func (d *Ikev2LivenessDescriptor) Retrieve(correlate []adapter.Ikev2LivenessKVWithMetadata) (dump []adapter.Ikev2LivenessKVWithMetadata, err error) {
	// dump Ikev2 Liveness
	return nil, nil
}
