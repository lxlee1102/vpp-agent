// Code generated by adapter-generator. DO NOT EDIT.

package adapter

import (
	"google.golang.org/protobuf/proto"
	. "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"
)

////////// type-safe key-value pair with metadata //////////

type TeibEntryKVWithMetadata struct {
	Key      string
	Value    *vpp_l3.TeibEntry
	Metadata interface{}
	Origin   ValueOrigin
}

////////// type-safe Descriptor structure //////////

type TeibEntryDescriptor struct {
	Name                 string
	KeySelector          KeySelector
	ValueTypeName        string
	KeyLabel             func(key string) string
	ValueComparator      func(key string, oldValue, newValue *vpp_l3.TeibEntry) bool
	NBKeyPrefix          string
	WithMetadata         bool
	MetadataMapFactory   MetadataMapFactory
	Validate             func(key string, value *vpp_l3.TeibEntry) error
	Create               func(key string, value *vpp_l3.TeibEntry) (metadata interface{}, err error)
	Delete               func(key string, value *vpp_l3.TeibEntry, metadata interface{}) error
	Update               func(key string, oldValue, newValue *vpp_l3.TeibEntry, oldMetadata interface{}) (newMetadata interface{}, err error)
	UpdateWithRecreate   func(key string, oldValue, newValue *vpp_l3.TeibEntry, metadata interface{}) bool
	Retrieve             func(correlate []TeibEntryKVWithMetadata) ([]TeibEntryKVWithMetadata, error)
	IsRetriableFailure   func(err error) bool
	DerivedValues        func(key string, value *vpp_l3.TeibEntry) []KeyValuePair
	Dependencies         func(key string, value *vpp_l3.TeibEntry) []Dependency
	RetrieveDependencies []string /* descriptor name */
}

////////// Descriptor adapter //////////

type TeibEntryDescriptorAdapter struct {
	descriptor *TeibEntryDescriptor
}

func NewTeibEntryDescriptor(typedDescriptor *TeibEntryDescriptor) *KVDescriptor {
	adapter := &TeibEntryDescriptorAdapter{descriptor: typedDescriptor}
	descriptor := &KVDescriptor{
		Name:                 typedDescriptor.Name,
		KeySelector:          typedDescriptor.KeySelector,
		ValueTypeName:        typedDescriptor.ValueTypeName,
		KeyLabel:             typedDescriptor.KeyLabel,
		NBKeyPrefix:          typedDescriptor.NBKeyPrefix,
		WithMetadata:         typedDescriptor.WithMetadata,
		MetadataMapFactory:   typedDescriptor.MetadataMapFactory,
		IsRetriableFailure:   typedDescriptor.IsRetriableFailure,
		RetrieveDependencies: typedDescriptor.RetrieveDependencies,
	}
	if typedDescriptor.ValueComparator != nil {
		descriptor.ValueComparator = adapter.ValueComparator
	}
	if typedDescriptor.Validate != nil {
		descriptor.Validate = adapter.Validate
	}
	if typedDescriptor.Create != nil {
		descriptor.Create = adapter.Create
	}
	if typedDescriptor.Delete != nil {
		descriptor.Delete = adapter.Delete
	}
	if typedDescriptor.Update != nil {
		descriptor.Update = adapter.Update
	}
	if typedDescriptor.UpdateWithRecreate != nil {
		descriptor.UpdateWithRecreate = adapter.UpdateWithRecreate
	}
	if typedDescriptor.Retrieve != nil {
		descriptor.Retrieve = adapter.Retrieve
	}
	if typedDescriptor.Dependencies != nil {
		descriptor.Dependencies = adapter.Dependencies
	}
	if typedDescriptor.DerivedValues != nil {
		descriptor.DerivedValues = adapter.DerivedValues
	}
	return descriptor
}

func (da *TeibEntryDescriptorAdapter) ValueComparator(key string, oldValue, newValue proto.Message) bool {
	typedOldValue, err1 := castTeibEntryValue(key, oldValue)
	typedNewValue, err2 := castTeibEntryValue(key, newValue)
	if err1 != nil || err2 != nil {
		return false
	}
	return da.descriptor.ValueComparator(key, typedOldValue, typedNewValue)
}

func (da *TeibEntryDescriptorAdapter) Validate(key string, value proto.Message) (err error) {
	typedValue, err := castTeibEntryValue(key, value)
	if err != nil {
		return err
	}
	return da.descriptor.Validate(key, typedValue)
}

func (da *TeibEntryDescriptorAdapter) Create(key string, value proto.Message) (metadata Metadata, err error) {
	typedValue, err := castTeibEntryValue(key, value)
	if err != nil {
		return nil, err
	}
	return da.descriptor.Create(key, typedValue)
}

func (da *TeibEntryDescriptorAdapter) Update(key string, oldValue, newValue proto.Message, oldMetadata Metadata) (newMetadata Metadata, err error) {
	oldTypedValue, err := castTeibEntryValue(key, oldValue)
	if err != nil {
		return nil, err
	}
	newTypedValue, err := castTeibEntryValue(key, newValue)
	if err != nil {
		return nil, err
	}
	typedOldMetadata, err := castTeibEntryMetadata(key, oldMetadata)
	if err != nil {
		return nil, err
	}
	return da.descriptor.Update(key, oldTypedValue, newTypedValue, typedOldMetadata)
}

func (da *TeibEntryDescriptorAdapter) Delete(key string, value proto.Message, metadata Metadata) error {
	typedValue, err := castTeibEntryValue(key, value)
	if err != nil {
		return err
	}
	typedMetadata, err := castTeibEntryMetadata(key, metadata)
	if err != nil {
		return err
	}
	return da.descriptor.Delete(key, typedValue, typedMetadata)
}

func (da *TeibEntryDescriptorAdapter) UpdateWithRecreate(key string, oldValue, newValue proto.Message, metadata Metadata) bool {
	oldTypedValue, err := castTeibEntryValue(key, oldValue)
	if err != nil {
		return true
	}
	newTypedValue, err := castTeibEntryValue(key, newValue)
	if err != nil {
		return true
	}
	typedMetadata, err := castTeibEntryMetadata(key, metadata)
	if err != nil {
		return true
	}
	return da.descriptor.UpdateWithRecreate(key, oldTypedValue, newTypedValue, typedMetadata)
}

func (da *TeibEntryDescriptorAdapter) Retrieve(correlate []KVWithMetadata) ([]KVWithMetadata, error) {
	var correlateWithType []TeibEntryKVWithMetadata
	for _, kvpair := range correlate {
		typedValue, err := castTeibEntryValue(kvpair.Key, kvpair.Value)
		if err != nil {
			continue
		}
		typedMetadata, err := castTeibEntryMetadata(kvpair.Key, kvpair.Metadata)
		if err != nil {
			continue
		}
		correlateWithType = append(correlateWithType,
			TeibEntryKVWithMetadata{
				Key:      kvpair.Key,
				Value:    typedValue,
				Metadata: typedMetadata,
				Origin:   kvpair.Origin,
			})
	}

	typedValues, err := da.descriptor.Retrieve(correlateWithType)
	if err != nil {
		return nil, err
	}
	var values []KVWithMetadata
	for _, typedKVWithMetadata := range typedValues {
		kvWithMetadata := KVWithMetadata{
			Key:      typedKVWithMetadata.Key,
			Metadata: typedKVWithMetadata.Metadata,
			Origin:   typedKVWithMetadata.Origin,
		}
		kvWithMetadata.Value = typedKVWithMetadata.Value
		values = append(values, kvWithMetadata)
	}
	return values, err
}

func (da *TeibEntryDescriptorAdapter) DerivedValues(key string, value proto.Message) []KeyValuePair {
	typedValue, err := castTeibEntryValue(key, value)
	if err != nil {
		return nil
	}
	return da.descriptor.DerivedValues(key, typedValue)
}

func (da *TeibEntryDescriptorAdapter) Dependencies(key string, value proto.Message) []Dependency {
	typedValue, err := castTeibEntryValue(key, value)
	if err != nil {
		return nil
	}
	return da.descriptor.Dependencies(key, typedValue)
}

////////// Helper methods //////////

func castTeibEntryValue(key string, value proto.Message) (*vpp_l3.TeibEntry, error) {
	typedValue, ok := value.(*vpp_l3.TeibEntry)
	if !ok {
		return nil, ErrInvalidValueType(key, value)
	}
	return typedValue, nil
}

func castTeibEntryMetadata(key string, metadata Metadata) (interface{}, error) {
	if metadata == nil {
		return nil, nil
	}
	typedMetadata, ok := metadata.(interface{})
	if !ok {
		return nil, ErrInvalidMetadataType(key)
	}
	return typedMetadata, nil
}
