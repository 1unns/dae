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
		keyBytes := make([]byte, 16)
		var val bpfTrafficStats
		iter := bpf.DeviceTrafficMap.Iterate()
		count := 0
		for iter.Next(&keyBytes, &val) {
			count++
			var ipStr string
			if isIPv4ZeroPrefix(keyBytesToArray(keyBytes)) {
				ipStr = net.IPv4(keyBytes[12], keyBytes[13], keyBytes[14], keyBytes[15]).String()
			} else {
				ipStr = net.IP(keyBytes).String()
			}
			devices = append(devices, DeviceTraffic{
				IP:            ipStr,
				UploadTotal:   val.UploadTotal,
				DownloadTotal: val.DownloadTotal,
			})
		}
		if err := iter.Err(); err != nil {
			logrus.Errorf("DeviceTrafficMap Iterate error: %v", err)
		}
	}

	if bpf.ConnTrafficMap != nil {
		keyBytes := make([]byte, 37)
		var val bpfTrafficStats
		iter := bpf.ConnTrafficMap.Iterate()
		count := 0
		for iter.Next(&keyBytes, &val) {
			count++
			var srcIpStr, dstIpStr string
			if isIPv4ZeroPrefix(keyBytesToArray(keyBytes[0:16])) {
				srcIpStr = net.IPv4(keyBytes[12], keyBytes[13], keyBytes[14], keyBytes[15]).String()
			} else {
				srcIpStr = net.IP(keyBytes[0:16]).String()
			}
			if isIPv4ZeroPrefix(keyBytesToArray(keyBytes[16:32])) {
				dstIpStr = net.IPv4(keyBytes[28], keyBytes[29], keyBytes[30], keyBytes[31]).String()
			} else {
				dstIpStr = net.IP(keyBytes[16:32]).String()
			}
			dport := binary.BigEndian.Uint16(keyBytes[34:36])
			conns = append(conns, ConnTraffic{
				SrcIP:         srcIpStr,
				DstIP:         dstIpStr,
				DstPort:       dport,
				UploadTotal:   val.UploadTotal,
				DownloadTotal: val.DownloadTotal,
			})
		}
		if err := iter.Err(); err != nil {
			logrus.Errorf("ConnTrafficMap Iterate error: %v", err)
		}
	}
	return devices, conns
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
