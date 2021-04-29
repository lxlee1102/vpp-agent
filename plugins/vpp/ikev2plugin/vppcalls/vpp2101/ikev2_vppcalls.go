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
	"fmt"

	vpp_ikev2 "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101/ikev2"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101/ip_types"
	ikev2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ikev2"
)

func (h *Ikev2VppHandler) AddProfile(prof *ikev2.Ikev2Profile) error {
	var err error

	// add profile
	err = h.AddProfileName(prof.Name)
	if err != nil {
		return err
	}

	// set profile auth
	err = h.SetProfileAuth(prof.Name, prof.Auth)
	if err != nil {
		goto ERR_EXIT
	}

	// set ids
	err = h.SetProfileIds(prof.Name, prof.Id)
	if err != nil {
		goto ERR_EXIT
	}

	// set responder
	if prof.Responder != nil {
		err = h.SetProfileResponder(prof.Name, prof.Responder)
		if err != nil {
			goto ERR_EXIT
		}
	}

	// set traffic-selector
	if len(prof.TrafficSelector) > 0 {
		err = h.SetProfileTS(prof.Name, prof.TrafficSelector)
		if err != nil {
			goto ERR_EXIT
		}
	}

	// set ikeTransforms
	if prof.IkeTransforms != nil {
		err = h.SetProfileIkeTs(prof.Name, prof.IkeTransforms)
		if err != nil {
			goto ERR_EXIT
		}
	}
	// set espTransforms
	if prof.EspTransforms != nil {
		err = h.SetProfileEspTs(prof.Name, prof.EspTransforms)
		if err != nil {
			goto ERR_EXIT
		}
	}

	// set lifetime args
	err = h.SetProfileSaLifetime(prof.Name, prof.LifeTime, prof.LifeTimeMaxdata, prof.LifeTimeJitter, prof.Handover)
	if err != nil {
		goto ERR_EXIT
	}

	//TODO:  set IpsecOverUDPPort, lost in vppctl ikev2 command. so dont add it.
	//err = h.SetProfileIpsecUDPPort(prof.Name, prof.IpsecOverUdpport)
	//if err != nil {
	//	goto ERR_EXIT
	//}

	// set tunInterface
	err = h.SetTunnelInterface(prof.Name, prof.TunnelInterface)
	if err != nil {
		goto ERR_EXIT
	}

	if prof.UdpEncap {
		err = h.SetUDPEncap(prof.Name)
		if err != nil {
			goto ERR_EXIT
		}
	}

	if prof.DisableNatt {
		err = h.SetDisableNatt(prof.Name)
		if err != nil {
			goto ERR_EXIT
		}
	}

	return nil

ERR_EXIT:
	h.RemoveProfile(prof.Name)
	return err
}

// Remove profile via binary API
func (h *Ikev2VppHandler) RemoveProfile(profile_id string) error {
	return h.profileAddDelName(profile_id, false)
}

// add profile id
func (h *Ikev2VppHandler) AddProfileName(name string) error {
	return h.profileAddDelName(name, true)
}

// del profile id
func (h *Ikev2VppHandler) DelProfileName(name string) error {
	return h.profileAddDelName(name, false)
}

func (h *Ikev2VppHandler) profileAddDelName(name string, isadd bool) error {
	request := &vpp_ikev2.Ikev2ProfileAddDel{
		Name:  name,
		IsAdd: isadd,
	}
	// prepare reply
	reply := &vpp_ikev2.Ikev2ProfileAddDelReply{}
	// send request and obtain reply
	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

// set profile auth
func (h *Ikev2VppHandler) SetProfileAuth(name string, auth *ikev2.Ikev2Profile_Auth) error {
	reqAuth := &vpp_ikev2.Ikev2ProfileSetAuth{
		Name:       name,
		AuthMethod: uint8(auth.Method),
		IsHex:      auth.Hex,
		DataLen:    uint32(len(auth.Data)),
		Data:       auth.Data,
	}
	replyAuth := &vpp_ikev2.Ikev2ProfileSetAuthReply{}
	if err := h.callsChannel.SendRequest(reqAuth).ReceiveReply(replyAuth); err != nil {
		return err
	}

	return nil
}

// set profile IDs

func (h *Ikev2VppHandler) SetProfileIds(name string, ids []*ikev2.Ikev2Profile_EndId) error {
	for _, v := range ids {
		reqId := &vpp_ikev2.Ikev2ProfileSetID{
			Name:    name,
			IsLocal: v.IsLocal,
			IDType:  uint8(v.Type),
			DataLen: uint32(len(v.Data)),
			Data:    []byte(v.Data),
		}
		replyId := &vpp_ikev2.Ikev2ProfileSetIDReply{}
		if err := h.callsChannel.SendRequest(reqId).ReceiveReply(replyId); err != nil {
			return err
		}
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileResponder(name string, rd *ikev2.Ikev2Profile_ResponderInfo) error {
	reqResponder := &vpp_ikev2.Ikev2SetResponder{
		Name: name,
	}

	if rd == nil {
		return nil
	}

	ifaceMeta, found := h.ifIndexes.LookupByName(rd.Interface)
	if !found {
		return fmt.Errorf("failed to get interface metadata for %v", rd.Interface)
	}
	reqResponder.Responder.SwIfIndex = vpp_ikev2.InterfaceIndex(ifaceMeta.SwIfIndex)
	ip, err := ip_types.ParseAddress(rd.Addr)
	if err != nil {
		return err
	}
	reqResponder.Responder.Addr.Af = vpp_ikev2.AddressFamily(ip.Af)
	reqResponder.Responder.Addr.Un = vpp_ikev2.AddressUnion(ip.Un)

	replyResponder := &vpp_ikev2.Ikev2SetResponderReply{}
	if err := h.callsChannel.SendRequest(reqResponder).ReceiveReply(replyResponder); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileTS(name string, tss []*ikev2.Ikev2Profile_TrafficSelector) error {
	if len(tss) == 0 {
		return nil
	}

	for _, v := range tss {
		tsTmp := vpp_ikev2.Ikev2Ts{
			SaIndex:      v.SaIndex,
			ChildSaIndex: v.ChildSaIndex,
			IsLocal:      v.IsLocal,
			ProtocolID:   uint8(v.Protocol),
			StartPort:    uint16(v.StartPort),
			EndPort:      uint16(v.EndPort),
			//StartAddr: v.StartAddr, // set below
			//EndAddr: v.EndAddr,
		}
		ipS, err := ip_types.ParseAddress(v.StartAddr)
		if err != nil {
			return err
		}
		ipE, err := ip_types.ParseAddress(v.EndAddr)
		if err != nil {
			return err
		}
		tsTmp.StartAddr = vpp_ikev2.Address{
			Af: vpp_ikev2.AddressFamily(ipS.Af),
			Un: vpp_ikev2.AddressUnion(ipS.Un),
		}
		tsTmp.EndAddr = vpp_ikev2.Address{
			Af: vpp_ikev2.AddressFamily(ipE.Af),
			Un: vpp_ikev2.AddressUnion(ipE.Un),
		}

		request := &vpp_ikev2.Ikev2ProfileSetTs{
			Name: name,
			Ts:   tsTmp,
		}

		reply := &vpp_ikev2.Ikev2ProfileSetTsReply{}
		if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
			return err
		}
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileIkeTs(name string, its *ikev2.Ikev2Profile_IkeTransforms) error {
	if its == nil {
		return nil
	}

	ikeT := vpp_ikev2.Ikev2IkeTransforms{
		CryptoAlg:     uint8(its.CryptoAlg),
		CryptoKeySize: its.CryptoKeySize,
		IntegAlg:      uint8(its.IntegAlg),
		DhGroup:       uint8(its.DhType),
	}

	request := &vpp_ikev2.Ikev2SetIkeTransforms{
		Name: name,
		Tr:   ikeT,
	}
	reply := &vpp_ikev2.Ikev2SetIkeTransformsReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileEspTs(name string, ets *ikev2.Ikev2Profile_EspTransforms) error {
	if ets == nil {
		return nil
	}

	espT := vpp_ikev2.Ikev2EspTransforms{
		CryptoAlg:     uint8(ets.CryptoAlg),
		CryptoKeySize: ets.CryptoKeySize,
		IntegAlg:      uint8(ets.IntegAlg),
	}

	request := &vpp_ikev2.Ikev2SetEspTransforms{
		Name: name,
		Tr:   espT,
	}
	reply := &vpp_ikev2.Ikev2SetEspTransformsReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileSaLifetime(name string, lifetime, maxData uint64, jitter, handover uint32) error {
	request := &vpp_ikev2.Ikev2SetSaLifetime{
		Name:            name,
		Lifetime:        lifetime,
		LifetimeMaxdata: maxData,
		LifetimeJitter:  jitter,
		Handover:        handover,
	}
	reply := &vpp_ikev2.Ikev2SetSaLifetimeReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetProfileIpsecUDPPort(name string, port uint32) error {
	return h.setProfileIpsecUDPPort(name, port, 1)
}

func (h *Ikev2VppHandler) DelProfileIpsecUDPPort(name string, port uint32) error {
	return h.setProfileIpsecUDPPort(name, port, 0)
}

func (h *Ikev2VppHandler) setProfileIpsecUDPPort(name string, port uint32, isSet uint8) error {
	request := &vpp_ikev2.Ikev2ProfileSetIpsecUDPPort{
		Name:  name,
		IsSet: 1,
		Port:  uint16(port),
	}
	reply := &vpp_ikev2.Ikev2ProfileSetIpsecUDPPortReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetTunnelInterface(name, ifname string) error {
	ifaceMeta, found := h.ifIndexes.LookupByName(ifname)
	if !found {
		return fmt.Errorf("failed to get interface metadata of %s", ifname)
	}

	request := &vpp_ikev2.Ikev2SetTunnelInterface{
		Name:      name,
		SwIfIndex: vpp_ikev2.InterfaceIndex(ifaceMeta.SwIfIndex),
	}
	reply := &vpp_ikev2.Ikev2SetTunnelInterfaceReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetUDPEncap(name string) error {
	request := &vpp_ikev2.Ikev2ProfileSetUDPEncap{
		Name: name,
	}

	reply := &vpp_ikev2.Ikev2ProfileSetUDPEncapReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}

func (h *Ikev2VppHandler) SetDisableNatt(name string) error {
	request := &vpp_ikev2.Ikev2ProfileDisableNatt{
		Name: name,
	}

	reply := &vpp_ikev2.Ikev2ProfileDisableNattReply{}

	if err := h.callsChannel.SendRequest(request).ReceiveReply(reply); err != nil {
		return err
	}

	return nil
}
