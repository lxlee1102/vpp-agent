// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: interface.proto

package interfaces

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type Interface_Type int32

const (
	Interface_UNDEFINED           Interface_Type = 0
	Interface_SOFTWARE_LOOPBACK   Interface_Type = 1
	Interface_ETHERNET_CSMACD     Interface_Type = 2
	Interface_MEMORY_INTERFACE    Interface_Type = 3
	Interface_TAP_INTERFACE       Interface_Type = 4
	Interface_AF_PACKET_INTERFACE Interface_Type = 5
	Interface_VXLAN_TUNNEL        Interface_Type = 6
)

var Interface_Type_name = map[int32]string{
	0: "UNDEFINED",
	1: "SOFTWARE_LOOPBACK",
	2: "ETHERNET_CSMACD",
	3: "MEMORY_INTERFACE",
	4: "TAP_INTERFACE",
	5: "AF_PACKET_INTERFACE",
	6: "VXLAN_TUNNEL",
}
var Interface_Type_value = map[string]int32{
	"UNDEFINED":           0,
	"SOFTWARE_LOOPBACK":   1,
	"ETHERNET_CSMACD":     2,
	"MEMORY_INTERFACE":    3,
	"TAP_INTERFACE":       4,
	"AF_PACKET_INTERFACE": 5,
	"VXLAN_TUNNEL":        6,
}

func (x Interface_Type) String() string {
	return proto.EnumName(Interface_Type_name, int32(x))
}
func (Interface_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 0}
}

// from vpp/build-root/install-vpp-native/vpp/include/vnet/interface.h
type Interface_RxModeSettings_RxModeType int32

const (
	Interface_RxModeSettings_UNKNOWN   Interface_RxModeSettings_RxModeType = 0
	Interface_RxModeSettings_POLLING   Interface_RxModeSettings_RxModeType = 1
	Interface_RxModeSettings_INTERRUPT Interface_RxModeSettings_RxModeType = 2
	Interface_RxModeSettings_ADAPTIVE  Interface_RxModeSettings_RxModeType = 3
	Interface_RxModeSettings_DEFAULT   Interface_RxModeSettings_RxModeType = 4
)

var Interface_RxModeSettings_RxModeType_name = map[int32]string{
	0: "UNKNOWN",
	1: "POLLING",
	2: "INTERRUPT",
	3: "ADAPTIVE",
	4: "DEFAULT",
}
var Interface_RxModeSettings_RxModeType_value = map[string]int32{
	"UNKNOWN":   0,
	"POLLING":   1,
	"INTERRUPT": 2,
	"ADAPTIVE":  3,
	"DEFAULT":   4,
}

func (x Interface_RxModeSettings_RxModeType) String() string {
	return proto.EnumName(Interface_RxModeSettings_RxModeType_name, int32(x))
}
func (Interface_RxModeSettings_RxModeType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 1, 0}
}

type Interface_MemifLink_MemifMode int32

const (
	Interface_MemifLink_ETHERNET    Interface_MemifLink_MemifMode = 0
	Interface_MemifLink_IP          Interface_MemifLink_MemifMode = 1
	Interface_MemifLink_PUNT_INJECT Interface_MemifLink_MemifMode = 2
)

var Interface_MemifLink_MemifMode_name = map[int32]string{
	0: "ETHERNET",
	1: "IP",
	2: "PUNT_INJECT",
}
var Interface_MemifLink_MemifMode_value = map[string]int32{
	"ETHERNET":    0,
	"IP":          1,
	"PUNT_INJECT": 2,
}

func (x Interface_MemifLink_MemifMode) String() string {
	return proto.EnumName(Interface_MemifLink_MemifMode_name, int32(x))
}
func (Interface_MemifLink_MemifMode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 3, 0}
}

type Interface struct {
	Name                string                         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Vrf                 uint32                         `protobuf:"varint,2,opt,name=vrf,proto3" json:"vrf,omitempty"`
	Type                Interface_Type                 `protobuf:"varint,3,opt,name=type,proto3,enum=interfaces.Interface_Type" json:"type,omitempty"`
	Enabled             bool                           `protobuf:"varint,4,opt,name=enabled,proto3" json:"enabled,omitempty"`
	PhysAddress         string                         `protobuf:"bytes,5,opt,name=phys_address,json=physAddress,proto3" json:"phys_address,omitempty"`
	IpAddresses         []string                       `protobuf:"bytes,6,rep,name=ip_addresses,json=ipAddresses" json:"ip_addresses,omitempty"`
	SetDhcpClient       bool                           `protobuf:"varint,7,opt,name=set_dhcp_client,json=setDhcpClient,proto3" json:"set_dhcp_client,omitempty"`
	Mtu                 uint32                         `protobuf:"varint,8,opt,name=mtu,proto3" json:"mtu,omitempty"`
	Unnumbered          *Interface_Unnumbered          `protobuf:"bytes,9,opt,name=unnumbered" json:"unnumbered,omitempty"`
	RxModeSettings      *Interface_RxModeSettings      `protobuf:"bytes,10,opt,name=rx_mode_settings,json=rxModeSettings" json:"rx_mode_settings,omitempty"`
	RxPlacementSettings *Interface_RxPlacementSettings `protobuf:"bytes,11,opt,name=rx_placement_settings,json=rxPlacementSettings" json:"rx_placement_settings,omitempty"`
	// Types that are valid to be assigned to Link:
	//	*Interface_Memif
	//	*Interface_Vxlan
	//	*Interface_Afpacket
	//	*Interface_Tap
	Link                 isInterface_Link `protobuf_oneof:"link"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Interface) Reset()         { *m = Interface{} }
func (m *Interface) String() string { return proto.CompactTextString(m) }
func (*Interface) ProtoMessage()    {}
func (*Interface) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0}
}
func (m *Interface) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface.Unmarshal(m, b)
}
func (m *Interface) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface.Marshal(b, m, deterministic)
}
func (dst *Interface) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface.Merge(dst, src)
}
func (m *Interface) XXX_Size() int {
	return xxx_messageInfo_Interface.Size(m)
}
func (m *Interface) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface.DiscardUnknown(m)
}

var xxx_messageInfo_Interface proto.InternalMessageInfo

type isInterface_Link interface {
	isInterface_Link()
}

type Interface_Memif struct {
	Memif *Interface_MemifLink `protobuf:"bytes,101,opt,name=memif,oneof"`
}
type Interface_Vxlan struct {
	Vxlan *Interface_VxlanLink `protobuf:"bytes,102,opt,name=vxlan,oneof"`
}
type Interface_Afpacket struct {
	Afpacket *Interface_AfpacketLink `protobuf:"bytes,103,opt,name=afpacket,oneof"`
}
type Interface_Tap struct {
	Tap *Interface_TapLink `protobuf:"bytes,104,opt,name=tap,oneof"`
}

func (*Interface_Memif) isInterface_Link()    {}
func (*Interface_Vxlan) isInterface_Link()    {}
func (*Interface_Afpacket) isInterface_Link() {}
func (*Interface_Tap) isInterface_Link()      {}

func (m *Interface) GetLink() isInterface_Link {
	if m != nil {
		return m.Link
	}
	return nil
}

func (m *Interface) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Interface) GetVrf() uint32 {
	if m != nil {
		return m.Vrf
	}
	return 0
}

func (m *Interface) GetType() Interface_Type {
	if m != nil {
		return m.Type
	}
	return Interface_UNDEFINED
}

func (m *Interface) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

func (m *Interface) GetPhysAddress() string {
	if m != nil {
		return m.PhysAddress
	}
	return ""
}

func (m *Interface) GetIpAddresses() []string {
	if m != nil {
		return m.IpAddresses
	}
	return nil
}

func (m *Interface) GetSetDhcpClient() bool {
	if m != nil {
		return m.SetDhcpClient
	}
	return false
}

func (m *Interface) GetMtu() uint32 {
	if m != nil {
		return m.Mtu
	}
	return 0
}

func (m *Interface) GetUnnumbered() *Interface_Unnumbered {
	if m != nil {
		return m.Unnumbered
	}
	return nil
}

func (m *Interface) GetRxModeSettings() *Interface_RxModeSettings {
	if m != nil {
		return m.RxModeSettings
	}
	return nil
}

func (m *Interface) GetRxPlacementSettings() *Interface_RxPlacementSettings {
	if m != nil {
		return m.RxPlacementSettings
	}
	return nil
}

func (m *Interface) GetMemif() *Interface_MemifLink {
	if x, ok := m.GetLink().(*Interface_Memif); ok {
		return x.Memif
	}
	return nil
}

func (m *Interface) GetVxlan() *Interface_VxlanLink {
	if x, ok := m.GetLink().(*Interface_Vxlan); ok {
		return x.Vxlan
	}
	return nil
}

func (m *Interface) GetAfpacket() *Interface_AfpacketLink {
	if x, ok := m.GetLink().(*Interface_Afpacket); ok {
		return x.Afpacket
	}
	return nil
}

func (m *Interface) GetTap() *Interface_TapLink {
	if x, ok := m.GetLink().(*Interface_Tap); ok {
		return x.Tap
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Interface) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Interface_OneofMarshaler, _Interface_OneofUnmarshaler, _Interface_OneofSizer, []interface{}{
		(*Interface_Memif)(nil),
		(*Interface_Vxlan)(nil),
		(*Interface_Afpacket)(nil),
		(*Interface_Tap)(nil),
	}
}

func _Interface_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Interface)
	// link
	switch x := m.Link.(type) {
	case *Interface_Memif:
		_ = b.EncodeVarint(101<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Memif); err != nil {
			return err
		}
	case *Interface_Vxlan:
		_ = b.EncodeVarint(102<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Vxlan); err != nil {
			return err
		}
	case *Interface_Afpacket:
		_ = b.EncodeVarint(103<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Afpacket); err != nil {
			return err
		}
	case *Interface_Tap:
		_ = b.EncodeVarint(104<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Tap); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Interface.Link has unexpected type %T", x)
	}
	return nil
}

func _Interface_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Interface)
	switch tag {
	case 101: // link.memif
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Interface_MemifLink)
		err := b.DecodeMessage(msg)
		m.Link = &Interface_Memif{msg}
		return true, err
	case 102: // link.vxlan
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Interface_VxlanLink)
		err := b.DecodeMessage(msg)
		m.Link = &Interface_Vxlan{msg}
		return true, err
	case 103: // link.afpacket
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Interface_AfpacketLink)
		err := b.DecodeMessage(msg)
		m.Link = &Interface_Afpacket{msg}
		return true, err
	case 104: // link.tap
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Interface_TapLink)
		err := b.DecodeMessage(msg)
		m.Link = &Interface_Tap{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Interface_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Interface)
	// link
	switch x := m.Link.(type) {
	case *Interface_Memif:
		s := proto.Size(x.Memif)
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Interface_Vxlan:
		s := proto.Size(x.Vxlan)
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Interface_Afpacket:
		s := proto.Size(x.Afpacket)
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Interface_Tap:
		s := proto.Size(x.Tap)
		n += 2 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Interface_Unnumbered struct {
	IsUnnumbered         bool     `protobuf:"varint,1,opt,name=is_unnumbered,json=isUnnumbered,proto3" json:"is_unnumbered,omitempty"`
	InterfaceWithIp      string   `protobuf:"bytes,2,opt,name=interface_with_ip,json=interfaceWithIp,proto3" json:"interface_with_ip,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Interface_Unnumbered) Reset()         { *m = Interface_Unnumbered{} }
func (m *Interface_Unnumbered) String() string { return proto.CompactTextString(m) }
func (*Interface_Unnumbered) ProtoMessage()    {}
func (*Interface_Unnumbered) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 0}
}
func (m *Interface_Unnumbered) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_Unnumbered.Unmarshal(m, b)
}
func (m *Interface_Unnumbered) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_Unnumbered.Marshal(b, m, deterministic)
}
func (dst *Interface_Unnumbered) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_Unnumbered.Merge(dst, src)
}
func (m *Interface_Unnumbered) XXX_Size() int {
	return xxx_messageInfo_Interface_Unnumbered.Size(m)
}
func (m *Interface_Unnumbered) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_Unnumbered.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_Unnumbered proto.InternalMessageInfo

func (m *Interface_Unnumbered) GetIsUnnumbered() bool {
	if m != nil {
		return m.IsUnnumbered
	}
	return false
}

func (m *Interface_Unnumbered) GetInterfaceWithIp() string {
	if m != nil {
		return m.InterfaceWithIp
	}
	return ""
}

type Interface_RxModeSettings struct {
	RxMode               Interface_RxModeSettings_RxModeType `protobuf:"varint,1,opt,name=rx_mode,json=rxMode,proto3,enum=interfaces.Interface_RxModeSettings_RxModeType" json:"rx_mode,omitempty"`
	QueueId              uint32                              `protobuf:"varint,2,opt,name=queue_id,json=queueId,proto3" json:"queue_id,omitempty"`
	QueueIdValid         uint32                              `protobuf:"varint,3,opt,name=queue_id_valid,json=queueIdValid,proto3" json:"queue_id_valid,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *Interface_RxModeSettings) Reset()         { *m = Interface_RxModeSettings{} }
func (m *Interface_RxModeSettings) String() string { return proto.CompactTextString(m) }
func (*Interface_RxModeSettings) ProtoMessage()    {}
func (*Interface_RxModeSettings) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 1}
}
func (m *Interface_RxModeSettings) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_RxModeSettings.Unmarshal(m, b)
}
func (m *Interface_RxModeSettings) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_RxModeSettings.Marshal(b, m, deterministic)
}
func (dst *Interface_RxModeSettings) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_RxModeSettings.Merge(dst, src)
}
func (m *Interface_RxModeSettings) XXX_Size() int {
	return xxx_messageInfo_Interface_RxModeSettings.Size(m)
}
func (m *Interface_RxModeSettings) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_RxModeSettings.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_RxModeSettings proto.InternalMessageInfo

func (m *Interface_RxModeSettings) GetRxMode() Interface_RxModeSettings_RxModeType {
	if m != nil {
		return m.RxMode
	}
	return Interface_RxModeSettings_UNKNOWN
}

func (m *Interface_RxModeSettings) GetQueueId() uint32 {
	if m != nil {
		return m.QueueId
	}
	return 0
}

func (m *Interface_RxModeSettings) GetQueueIdValid() uint32 {
	if m != nil {
		return m.QueueIdValid
	}
	return 0
}

type Interface_RxPlacementSettings struct {
	Queue                uint32   `protobuf:"varint,1,opt,name=queue,proto3" json:"queue,omitempty"`
	Worker               uint32   `protobuf:"varint,2,opt,name=worker,proto3" json:"worker,omitempty"`
	IsMain               bool     `protobuf:"varint,3,opt,name=is_main,json=isMain,proto3" json:"is_main,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Interface_RxPlacementSettings) Reset()         { *m = Interface_RxPlacementSettings{} }
func (m *Interface_RxPlacementSettings) String() string { return proto.CompactTextString(m) }
func (*Interface_RxPlacementSettings) ProtoMessage()    {}
func (*Interface_RxPlacementSettings) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 2}
}
func (m *Interface_RxPlacementSettings) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_RxPlacementSettings.Unmarshal(m, b)
}
func (m *Interface_RxPlacementSettings) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_RxPlacementSettings.Marshal(b, m, deterministic)
}
func (dst *Interface_RxPlacementSettings) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_RxPlacementSettings.Merge(dst, src)
}
func (m *Interface_RxPlacementSettings) XXX_Size() int {
	return xxx_messageInfo_Interface_RxPlacementSettings.Size(m)
}
func (m *Interface_RxPlacementSettings) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_RxPlacementSettings.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_RxPlacementSettings proto.InternalMessageInfo

func (m *Interface_RxPlacementSettings) GetQueue() uint32 {
	if m != nil {
		return m.Queue
	}
	return 0
}

func (m *Interface_RxPlacementSettings) GetWorker() uint32 {
	if m != nil {
		return m.Worker
	}
	return 0
}

func (m *Interface_RxPlacementSettings) GetIsMain() bool {
	if m != nil {
		return m.IsMain
	}
	return false
}

type Interface_MemifLink struct {
	Master               bool                          `protobuf:"varint,1,opt,name=master,proto3" json:"master,omitempty"`
	Mode                 Interface_MemifLink_MemifMode `protobuf:"varint,2,opt,name=mode,proto3,enum=interfaces.Interface_MemifLink_MemifMode" json:"mode,omitempty"`
	Id                   uint32                        `protobuf:"varint,3,opt,name=id,proto3" json:"id,omitempty"`
	SocketFilename       string                        `protobuf:"bytes,4,opt,name=socket_filename,json=socketFilename,proto3" json:"socket_filename,omitempty"`
	Secret               string                        `protobuf:"bytes,5,opt,name=secret,proto3" json:"secret,omitempty"`
	RingSize             uint32                        `protobuf:"varint,6,opt,name=ring_size,json=ringSize,proto3" json:"ring_size,omitempty"`
	BufferSize           uint32                        `protobuf:"varint,7,opt,name=buffer_size,json=bufferSize,proto3" json:"buffer_size,omitempty"`
	RxQueues             uint32                        `protobuf:"varint,8,opt,name=rx_queues,json=rxQueues,proto3" json:"rx_queues,omitempty"`
	TxQueues             uint32                        `protobuf:"varint,9,opt,name=tx_queues,json=txQueues,proto3" json:"tx_queues,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *Interface_MemifLink) Reset()         { *m = Interface_MemifLink{} }
func (m *Interface_MemifLink) String() string { return proto.CompactTextString(m) }
func (*Interface_MemifLink) ProtoMessage()    {}
func (*Interface_MemifLink) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 3}
}
func (m *Interface_MemifLink) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_MemifLink.Unmarshal(m, b)
}
func (m *Interface_MemifLink) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_MemifLink.Marshal(b, m, deterministic)
}
func (dst *Interface_MemifLink) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_MemifLink.Merge(dst, src)
}
func (m *Interface_MemifLink) XXX_Size() int {
	return xxx_messageInfo_Interface_MemifLink.Size(m)
}
func (m *Interface_MemifLink) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_MemifLink.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_MemifLink proto.InternalMessageInfo

func (m *Interface_MemifLink) GetMaster() bool {
	if m != nil {
		return m.Master
	}
	return false
}

func (m *Interface_MemifLink) GetMode() Interface_MemifLink_MemifMode {
	if m != nil {
		return m.Mode
	}
	return Interface_MemifLink_ETHERNET
}

func (m *Interface_MemifLink) GetId() uint32 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *Interface_MemifLink) GetSocketFilename() string {
	if m != nil {
		return m.SocketFilename
	}
	return ""
}

func (m *Interface_MemifLink) GetSecret() string {
	if m != nil {
		return m.Secret
	}
	return ""
}

func (m *Interface_MemifLink) GetRingSize() uint32 {
	if m != nil {
		return m.RingSize
	}
	return 0
}

func (m *Interface_MemifLink) GetBufferSize() uint32 {
	if m != nil {
		return m.BufferSize
	}
	return 0
}

func (m *Interface_MemifLink) GetRxQueues() uint32 {
	if m != nil {
		return m.RxQueues
	}
	return 0
}

func (m *Interface_MemifLink) GetTxQueues() uint32 {
	if m != nil {
		return m.TxQueues
	}
	return 0
}

type Interface_VxlanLink struct {
	SrcAddress           string   `protobuf:"bytes,1,opt,name=src_address,json=srcAddress,proto3" json:"src_address,omitempty"`
	DstAddress           string   `protobuf:"bytes,2,opt,name=dst_address,json=dstAddress,proto3" json:"dst_address,omitempty"`
	Vni                  uint32   `protobuf:"varint,3,opt,name=vni,proto3" json:"vni,omitempty"`
	Multicast            string   `protobuf:"bytes,4,opt,name=multicast,proto3" json:"multicast,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Interface_VxlanLink) Reset()         { *m = Interface_VxlanLink{} }
func (m *Interface_VxlanLink) String() string { return proto.CompactTextString(m) }
func (*Interface_VxlanLink) ProtoMessage()    {}
func (*Interface_VxlanLink) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 4}
}
func (m *Interface_VxlanLink) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_VxlanLink.Unmarshal(m, b)
}
func (m *Interface_VxlanLink) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_VxlanLink.Marshal(b, m, deterministic)
}
func (dst *Interface_VxlanLink) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_VxlanLink.Merge(dst, src)
}
func (m *Interface_VxlanLink) XXX_Size() int {
	return xxx_messageInfo_Interface_VxlanLink.Size(m)
}
func (m *Interface_VxlanLink) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_VxlanLink.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_VxlanLink proto.InternalMessageInfo

func (m *Interface_VxlanLink) GetSrcAddress() string {
	if m != nil {
		return m.SrcAddress
	}
	return ""
}

func (m *Interface_VxlanLink) GetDstAddress() string {
	if m != nil {
		return m.DstAddress
	}
	return ""
}

func (m *Interface_VxlanLink) GetVni() uint32 {
	if m != nil {
		return m.Vni
	}
	return 0
}

func (m *Interface_VxlanLink) GetMulticast() string {
	if m != nil {
		return m.Multicast
	}
	return ""
}

type Interface_AfpacketLink struct {
	HostIfName           string   `protobuf:"bytes,1,opt,name=host_if_name,json=hostIfName,proto3" json:"host_if_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Interface_AfpacketLink) Reset()         { *m = Interface_AfpacketLink{} }
func (m *Interface_AfpacketLink) String() string { return proto.CompactTextString(m) }
func (*Interface_AfpacketLink) ProtoMessage()    {}
func (*Interface_AfpacketLink) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 5}
}
func (m *Interface_AfpacketLink) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_AfpacketLink.Unmarshal(m, b)
}
func (m *Interface_AfpacketLink) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_AfpacketLink.Marshal(b, m, deterministic)
}
func (dst *Interface_AfpacketLink) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_AfpacketLink.Merge(dst, src)
}
func (m *Interface_AfpacketLink) XXX_Size() int {
	return xxx_messageInfo_Interface_AfpacketLink.Size(m)
}
func (m *Interface_AfpacketLink) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_AfpacketLink.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_AfpacketLink proto.InternalMessageInfo

func (m *Interface_AfpacketLink) GetHostIfName() string {
	if m != nil {
		return m.HostIfName
	}
	return ""
}

type Interface_TapLink struct {
	Version              uint32   `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	HostIfName           string   `protobuf:"bytes,2,opt,name=host_if_name,json=hostIfName,proto3" json:"host_if_name,omitempty"`
	ToMicroservice       string   `protobuf:"bytes,3,opt,name=to_microservice,json=toMicroservice,proto3" json:"to_microservice,omitempty"`
	RxRingSize           uint32   `protobuf:"varint,4,opt,name=rx_ring_size,json=rxRingSize,proto3" json:"rx_ring_size,omitempty"`
	TxRingSize           uint32   `protobuf:"varint,5,opt,name=tx_ring_size,json=txRingSize,proto3" json:"tx_ring_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Interface_TapLink) Reset()         { *m = Interface_TapLink{} }
func (m *Interface_TapLink) String() string { return proto.CompactTextString(m) }
func (*Interface_TapLink) ProtoMessage()    {}
func (*Interface_TapLink) Descriptor() ([]byte, []int) {
	return fileDescriptor_interface_c19779f243337e56, []int{0, 6}
}
func (m *Interface_TapLink) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Interface_TapLink.Unmarshal(m, b)
}
func (m *Interface_TapLink) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Interface_TapLink.Marshal(b, m, deterministic)
}
func (dst *Interface_TapLink) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Interface_TapLink.Merge(dst, src)
}
func (m *Interface_TapLink) XXX_Size() int {
	return xxx_messageInfo_Interface_TapLink.Size(m)
}
func (m *Interface_TapLink) XXX_DiscardUnknown() {
	xxx_messageInfo_Interface_TapLink.DiscardUnknown(m)
}

var xxx_messageInfo_Interface_TapLink proto.InternalMessageInfo

func (m *Interface_TapLink) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Interface_TapLink) GetHostIfName() string {
	if m != nil {
		return m.HostIfName
	}
	return ""
}

func (m *Interface_TapLink) GetToMicroservice() string {
	if m != nil {
		return m.ToMicroservice
	}
	return ""
}

func (m *Interface_TapLink) GetRxRingSize() uint32 {
	if m != nil {
		return m.RxRingSize
	}
	return 0
}

func (m *Interface_TapLink) GetTxRingSize() uint32 {
	if m != nil {
		return m.TxRingSize
	}
	return 0
}

func init() {
	proto.RegisterType((*Interface)(nil), "interfaces.Interface")
	proto.RegisterType((*Interface_Unnumbered)(nil), "interfaces.Interface.Unnumbered")
	proto.RegisterType((*Interface_RxModeSettings)(nil), "interfaces.Interface.RxModeSettings")
	proto.RegisterType((*Interface_RxPlacementSettings)(nil), "interfaces.Interface.RxPlacementSettings")
	proto.RegisterType((*Interface_MemifLink)(nil), "interfaces.Interface.MemifLink")
	proto.RegisterType((*Interface_VxlanLink)(nil), "interfaces.Interface.VxlanLink")
	proto.RegisterType((*Interface_AfpacketLink)(nil), "interfaces.Interface.AfpacketLink")
	proto.RegisterType((*Interface_TapLink)(nil), "interfaces.Interface.TapLink")
	proto.RegisterEnum("interfaces.Interface_Type", Interface_Type_name, Interface_Type_value)
	proto.RegisterEnum("interfaces.Interface_RxModeSettings_RxModeType", Interface_RxModeSettings_RxModeType_name, Interface_RxModeSettings_RxModeType_value)
	proto.RegisterEnum("interfaces.Interface_MemifLink_MemifMode", Interface_MemifLink_MemifMode_name, Interface_MemifLink_MemifMode_value)
}

func init() { proto.RegisterFile("interface.proto", fileDescriptor_interface_c19779f243337e56) }

var fileDescriptor_interface_c19779f243337e56 = []byte{
	// 1047 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x55, 0xdd, 0x72, 0xdb, 0x44,
	0x14, 0x8e, 0x1c, 0xc7, 0xb6, 0x8e, 0xff, 0xd4, 0x4d, 0x4b, 0x85, 0x81, 0xa9, 0x09, 0x1d, 0x48,
	0xb9, 0x08, 0x10, 0x2e, 0xb8, 0x62, 0xa6, 0xaa, 0x2d, 0x53, 0x53, 0x5b, 0x36, 0x8a, 0x9c, 0xc0,
	0x0c, 0x9d, 0x1d, 0x45, 0x5a, 0xc7, 0x3b, 0xb1, 0x64, 0xb1, 0xbb, 0x4e, 0x9d, 0xce, 0xf0, 0x18,
	0xbc, 0x08, 0x2f, 0xc4, 0x2d, 0x37, 0xbc, 0x03, 0xb3, 0xab, 0x1f, 0xbb, 0x34, 0x05, 0xee, 0xf6,
	0x7c, 0xe7, 0x3b, 0xdf, 0xee, 0x9e, 0x9f, 0x5d, 0x68, 0xd3, 0x58, 0x10, 0x36, 0xf7, 0x03, 0x72,
	0x92, 0xb0, 0x95, 0x58, 0x21, 0x28, 0x00, 0x7e, 0xf4, 0x67, 0x1b, 0xf4, 0x61, 0x6e, 0x22, 0x04,
	0xe5, 0xd8, 0x8f, 0x88, 0xa9, 0x75, 0xb5, 0x63, 0xdd, 0x55, 0x6b, 0x64, 0xc0, 0xfe, 0x0d, 0x9b,
	0x9b, 0xa5, 0xae, 0x76, 0xdc, 0x74, 0xe5, 0x12, 0x9d, 0x40, 0x59, 0xdc, 0x26, 0xc4, 0xdc, 0xef,
	0x6a, 0xc7, 0xad, 0xd3, 0xce, 0xc9, 0x56, 0xee, 0xa4, 0x90, 0x3a, 0xf1, 0x6e, 0x13, 0xe2, 0x2a,
	0x1e, 0x32, 0xa1, 0x4a, 0x62, 0xff, 0x72, 0x49, 0x42, 0xb3, 0xdc, 0xd5, 0x8e, 0x6b, 0x6e, 0x6e,
	0xa2, 0x8f, 0xa1, 0x91, 0x2c, 0x6e, 0x39, 0xf6, 0xc3, 0x90, 0x11, 0xce, 0xcd, 0x03, 0xb5, 0x6f,
	0x5d, 0x62, 0x56, 0x0a, 0x49, 0x0a, 0x4d, 0x72, 0x02, 0xe1, 0x66, 0xa5, 0xbb, 0x2f, 0x29, 0x34,
	0xb1, 0x72, 0x08, 0x7d, 0x0a, 0x6d, 0x4e, 0x04, 0x0e, 0x17, 0x41, 0x82, 0x83, 0x25, 0x25, 0xb1,
	0x30, 0xab, 0x6a, 0x9f, 0x26, 0x27, 0xa2, 0xbf, 0x08, 0x92, 0x9e, 0x02, 0xe5, 0x4d, 0x22, 0xb1,
	0x36, 0x6b, 0xe9, 0x4d, 0x22, 0xb1, 0x46, 0x4f, 0x01, 0xd6, 0x71, 0xbc, 0x8e, 0x2e, 0x09, 0x23,
	0xa1, 0xa9, 0x77, 0xb5, 0xe3, 0xfa, 0x69, 0xf7, 0xee, 0xfb, 0xcc, 0x0a, 0x9e, 0xbb, 0x13, 0x83,
	0x1c, 0x30, 0xd8, 0x06, 0x47, 0xab, 0x90, 0x60, 0x4e, 0x84, 0xa0, 0xf1, 0x15, 0x37, 0x41, 0xe9,
	0x3c, 0xbe, 0x5b, 0xc7, 0xdd, 0x8c, 0x57, 0x21, 0x39, 0xcb, 0xb8, 0x6e, 0x8b, 0xbd, 0x61, 0xa3,
	0x97, 0xf0, 0x80, 0x6d, 0x70, 0xb2, 0xf4, 0x03, 0x12, 0x91, 0x58, 0x6c, 0x45, 0xeb, 0x4a, 0xf4,
	0xc9, 0xbb, 0x44, 0xa7, 0x79, 0x44, 0xa1, 0x7c, 0xc8, 0xde, 0x06, 0xd1, 0x37, 0x70, 0x10, 0x91,
	0x88, 0xce, 0x4d, 0xa2, 0xe4, 0x1e, 0xdd, 0x2d, 0x37, 0x96, 0x94, 0x11, 0x8d, 0xaf, 0x9f, 0xef,
	0xb9, 0x29, 0x5f, 0x06, 0xde, 0x6c, 0x96, 0x7e, 0x6c, 0xce, 0xff, 0x2d, 0xf0, 0x5c, 0x52, 0xf2,
	0x40, 0xc5, 0x47, 0x4f, 0xa1, 0xe6, 0xcf, 0x13, 0x3f, 0xb8, 0x26, 0xc2, 0xbc, 0x52, 0xb1, 0x47,
	0x77, 0xc7, 0x5a, 0x19, 0x2b, 0x0b, 0x2f, 0xa2, 0xd0, 0x57, 0xb0, 0x2f, 0xfc, 0xc4, 0x5c, 0xa8,
	0xe0, 0x8f, 0xde, 0xd1, 0x6d, 0x7e, 0x92, 0xc5, 0x49, 0x6e, 0xe7, 0x25, 0xc0, 0xb6, 0x5e, 0xe8,
	0x13, 0x68, 0x52, 0x8e, 0x77, 0x0a, 0xad, 0xa9, 0xee, 0x68, 0x50, 0xbe, 0x43, 0xfa, 0x1c, 0xee,
	0x15, 0xca, 0xf8, 0x15, 0x15, 0x0b, 0x4c, 0x13, 0xd5, 0xf4, 0xba, 0xbb, 0x1d, 0xa0, 0x0b, 0x2a,
	0x16, 0xc3, 0xa4, 0xf3, 0x97, 0x06, 0xad, 0x37, 0xeb, 0x88, 0x9e, 0x43, 0x35, 0xeb, 0x03, 0xa5,
	0xde, 0x3a, 0xfd, 0xe2, 0xff, 0x94, 0x3f, 0x33, 0xd5, 0xac, 0x54, 0xd2, 0x4e, 0x40, 0xef, 0x43,
	0xed, 0x97, 0x35, 0x59, 0x13, 0x4c, 0xc3, 0x6c, 0xe8, 0xaa, 0xca, 0x1e, 0x86, 0xe8, 0x31, 0xb4,
	0x72, 0x17, 0xbe, 0xf1, 0x97, 0x34, 0x54, 0x23, 0xd8, 0x74, 0x1b, 0x19, 0xe1, 0x5c, 0x62, 0x47,
	0x53, 0x80, 0xad, 0x2c, 0xaa, 0x43, 0x75, 0xe6, 0xbc, 0x70, 0x26, 0x17, 0x8e, 0xb1, 0x27, 0x8d,
	0xe9, 0x64, 0x34, 0x1a, 0x3a, 0xdf, 0x19, 0x1a, 0x6a, 0x82, 0x3e, 0x74, 0x3c, 0xdb, 0x75, 0x67,
	0x53, 0xcf, 0x28, 0xa1, 0x06, 0xd4, 0xac, 0xbe, 0x35, 0xf5, 0x86, 0xe7, 0xb6, 0xb1, 0x2f, 0x99,
	0x7d, 0x7b, 0x60, 0xcd, 0x46, 0x9e, 0x51, 0xee, 0xfc, 0x0c, 0x87, 0x77, 0x74, 0x18, 0xba, 0x0f,
	0x07, 0x6a, 0x63, 0x75, 0xe3, 0xa6, 0x9b, 0x1a, 0xe8, 0x3d, 0xa8, 0xbc, 0x5a, 0xb1, 0x6b, 0xc2,
	0xb2, 0xd3, 0x67, 0x16, 0x7a, 0x08, 0x55, 0xca, 0x71, 0xe4, 0xd3, 0x58, 0x9d, 0xba, 0xe6, 0x56,
	0x28, 0x1f, 0xfb, 0x34, 0xee, 0xfc, 0x51, 0x02, 0xbd, 0xe8, 0x38, 0x19, 0x1e, 0xf9, 0x5c, 0x10,
	0x96, 0x55, 0x29, 0xb3, 0xd0, 0xb7, 0x50, 0x56, 0xd9, 0x2d, 0xa9, 0xec, 0x3e, 0xf9, 0x8f, 0xc6,
	0x4d, 0x57, 0x32, 0x09, 0xae, 0x0a, 0x43, 0x2d, 0x28, 0x15, 0xe9, 0x2a, 0xd1, 0x10, 0x7d, 0x06,
	0x6d, 0xbe, 0x92, 0xed, 0x85, 0xe7, 0x74, 0x49, 0xd4, 0xa3, 0x57, 0x56, 0xc5, 0x6e, 0xa5, 0xf0,
	0x20, 0x43, 0xe5, 0x79, 0x38, 0x09, 0x18, 0x11, 0xd9, 0xe3, 0x94, 0x59, 0xe8, 0x03, 0xd0, 0x19,
	0x8d, 0xaf, 0x30, 0xa7, 0xaf, 0x89, 0x59, 0x51, 0xba, 0x35, 0x09, 0x9c, 0xd1, 0xd7, 0x04, 0x3d,
	0x82, 0xfa, 0xe5, 0x7a, 0x3e, 0x27, 0x2c, 0x75, 0x57, 0x95, 0x1b, 0x52, 0x48, 0x11, 0x64, 0xf4,
	0x06, 0xab, 0x84, 0xf1, 0xec, 0x41, 0xaa, 0xb1, 0xcd, 0x0f, 0xca, 0x96, 0x4e, 0x51, 0x38, 0xf5,
	0xd4, 0x29, 0x32, 0xe7, 0xd1, 0x69, 0x96, 0x2c, 0xd5, 0x2b, 0x0d, 0xa8, 0xd9, 0xde, 0x73, 0xdb,
	0x75, 0x6c, 0xcf, 0xd8, 0x43, 0x15, 0x28, 0x0d, 0xa7, 0x86, 0x86, 0xda, 0x50, 0x9f, 0xce, 0x1c,
	0x0f, 0x0f, 0x9d, 0xef, 0xed, 0x9e, 0x67, 0x94, 0x3a, 0xbf, 0x82, 0x5e, 0x4c, 0xa6, 0x3c, 0x1b,
	0x67, 0x41, 0xf1, 0xe4, 0xa6, 0x4f, 0x3d, 0x70, 0x16, 0xe4, 0x2f, 0xee, 0x23, 0xa8, 0x87, 0x5c,
	0x14, 0x84, 0x74, 0x06, 0x20, 0xe4, 0x22, 0x27, 0xc8, 0x1f, 0x21, 0xa6, 0x59, 0x32, 0xe5, 0x12,
	0x7d, 0x08, 0x7a, 0xb4, 0x5e, 0x0a, 0x1a, 0xf8, 0x5c, 0x64, 0x79, 0xdc, 0x02, 0x9d, 0x2f, 0xa1,
	0xb1, 0x3b, 0xdc, 0xa8, 0x0b, 0x8d, 0xc5, 0x8a, 0x0b, 0x4c, 0xe7, 0x78, 0xe7, 0xb7, 0x01, 0x89,
	0x0d, 0xe7, 0x8e, 0x1f, 0x91, 0xce, 0xef, 0x1a, 0x54, 0xb3, 0x91, 0x96, 0xbf, 0xc7, 0x0d, 0x61,
	0x9c, 0xae, 0xe2, 0xac, 0xcf, 0x72, 0xf3, 0x2d, 0x9d, 0xd2, 0x3f, 0x75, 0x64, 0x95, 0xc5, 0x0a,
	0x47, 0x34, 0x60, 0x2b, 0x4e, 0xd8, 0x0d, 0x0d, 0xd2, 0x4f, 0x4b, 0x77, 0x5b, 0x62, 0x35, 0xde,
	0x41, 0xa5, 0x14, 0xdb, 0xe0, 0x6d, 0x41, 0xcb, 0x69, 0xc5, 0xd8, 0xc6, 0xcd, 0x4b, 0xda, 0x85,
	0x86, 0xd8, 0x65, 0x1c, 0xa4, 0x0c, 0x51, 0x30, 0x8e, 0x7e, 0xd3, 0xa0, 0xac, 0x46, 0xae, 0x09,
	0xfa, 0xcc, 0xe9, 0xdb, 0x83, 0xa1, 0x63, 0xf7, 0x8d, 0x3d, 0xf4, 0x00, 0xee, 0x9d, 0x4d, 0x06,
	0xde, 0x85, 0xe5, 0xda, 0x78, 0x34, 0x99, 0x4c, 0x9f, 0x59, 0xbd, 0x17, 0x86, 0x86, 0x0e, 0xa1,
	0x9d, 0xd7, 0x0e, 0xf7, 0xce, 0xc6, 0x56, 0xaf, 0x6f, 0x94, 0xd0, 0x7d, 0x30, 0xc6, 0xf6, 0x78,
	0xe2, 0xfe, 0x84, 0xd5, 0x68, 0x0e, 0xac, 0x9e, 0x1c, 0xc6, 0x7b, 0xd0, 0xf4, 0xac, 0xe9, 0x0e,
	0x54, 0x46, 0x0f, 0xe1, 0xd0, 0x1a, 0xe0, 0xa9, 0xd5, 0x7b, 0x61, 0x7b, 0x3b, 0x8e, 0x03, 0x64,
	0x40, 0xe3, 0xfc, 0xc7, 0x91, 0xe5, 0x60, 0x6f, 0xe6, 0x38, 0xf6, 0xc8, 0xa8, 0x3c, 0xab, 0x40,
	0x79, 0x49, 0xe3, 0xeb, 0xcb, 0x8a, 0xfa, 0xfd, 0xbf, 0xfe, 0x3b, 0x00, 0x00, 0xff, 0xff, 0xef,
	0xe0, 0x25, 0x6d, 0x10, 0x08, 0x00, 0x00,
}
