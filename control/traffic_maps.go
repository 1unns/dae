/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net"

	"github.com/sirupsen/logrus"
)

// ReadTrafficMaps reads device and connection traffic statistics from eBPF maps.
// Returns empty slices if the maps are not available (e.g., before make ebpf is run).
func (c *controlPlaneCore) ReadTrafficMaps() (devices []DeviceTraffic, conns []ConnTraffic) {
	if c == nil {
		return nil, nil
	}
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil, nil
	}

	if bpf.DeviceTrafficMap != nil {
		var key [16]byte
		var val bpfTrafficStats
		iter := bpf.DeviceTrafficMap.Iterate()
		count := 0
		for iter.Next(&key, &val) {
			count++
			var ipStr string
			if isIPv4ZeroPrefix(key) {
				ipStr = net.IPv4(key[12], key[13], key[14], key[15]).String()
			} else {
				ipStr = net.IP(key[:]).String()
			}
			devices = append(devices, DeviceTraffic{
				IP:                  ipStr,
				ProxyUploadTotal:    val.ProxyUploadTotal,
				ProxyDownloadTotal:  val.ProxyDownloadTotal,
				DirectUploadTotal:   val.DirectUploadTotal,
				DirectDownloadTotal: val.DirectDownloadTotal,
			})
		}
		if err := iter.Err(); err != nil {
			logrus.Errorf("DeviceTrafficMap Iterate error: %v", err)
		}
	}

	if bpf.ConnTrafficMap != nil {
		var key bpfTuplesKey
		var val bpfTrafficStats
		iter := bpf.ConnTrafficMap.Iterate()
		count := 0
		for iter.Next(&key, &val) {
			count++
			var srcIpStr, dstIpStr string
			if isIPv4ZeroPrefix(key.Sip.U6Addr8) {
				srcIpStr = net.IPv4(key.Sip.U6Addr8[12], key.Sip.U6Addr8[13], key.Sip.U6Addr8[14], key.Sip.U6Addr8[15]).String()
			} else {
				srcIpStr = net.IP(key.Sip.U6Addr8[:]).String()
			}
			if isIPv4ZeroPrefix(key.Dip.U6Addr8) {
				dstIpStr = net.IPv4(key.Dip.U6Addr8[28-16], key.Dip.U6Addr8[29-16], key.Dip.U6Addr8[30-16], key.Dip.U6Addr8[31-16]).String()
			} else {
				dstIpStr = net.IP(key.Dip.U6Addr8[:]).String()
			}
			// Port is in network byte order in bpfTuplesKey?
			// Wait, let's just use binary.BigEndian on a byte slice to be safe if it's network byte order
			dportBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(dportBytes, key.Dport)
			dport := binary.BigEndian.Uint16(dportBytes)

			conns = append(conns, ConnTraffic{
				SrcIP:         srcIpStr,
				DstIP:         dstIpStr,
				DstPort:       dport,
				UploadTotal:   val.ProxyUploadTotal + val.DirectUploadTotal,
				DownloadTotal: val.ProxyDownloadTotal + val.DirectDownloadTotal,
			})
		}
		if err := iter.Err(); err != nil {
			logrus.Errorf("ConnTrafficMap Iterate error: %v", err)
		}
	}
	return devices, conns
}

// ClearTrafficMaps clears the traffic statistics eBPF maps.
func (c *ControlPlane) ClearTrafficMaps() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.ClearTrafficMaps()
}

func (c *controlPlaneCore) ClearTrafficMaps() error {
	if c == nil {
		return nil
	}
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil
	}

	if bpf.DeviceTrafficMap != nil {
		// Iterate and collect all keys
		var keysToDelete [][16]byte
		var key [16]byte
		var val bpfTrafficStats
		iter := bpf.DeviceTrafficMap.Iterate()
		for iter.Next(&key, &val) {
			keysToDelete = append(keysToDelete, key)
		}
		if len(keysToDelete) > 0 {
			_, err := BpfMapBatchDelete(bpf.DeviceTrafficMap, keysToDelete)
			if err != nil {
				logrus.Errorf("ClearTrafficMaps: DeviceTrafficMap batch delete error: %v", err)
			}
		}
	}

	if bpf.ConnTrafficMap != nil {
		var keysToDelete []bpfTuplesKey
		var key bpfTuplesKey
		var val bpfTrafficStats
		iter := bpf.ConnTrafficMap.Iterate()
		for iter.Next(&key, &val) {
			keysToDelete = append(keysToDelete, key)
		}
		if len(keysToDelete) > 0 {
			_, err := BpfMapBatchDelete(bpf.ConnTrafficMap, keysToDelete)
			if err != nil {
				logrus.Errorf("ClearTrafficMaps: ConnTrafficMap batch delete error: %v", err)
			}
		}
	}

	return nil
}


// keyBytesToArray converts a byte slice to a [16]uint8 array for isIPv4ZeroPrefix.
func keyBytesToArray(b []byte) [16]uint8 {
	var arr [16]uint8
	copy(arr[:], b)
	return arr
}

func isIPv4ZeroPrefix(ip [16]uint8) bool {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 255 && ip[11] == 255
}
