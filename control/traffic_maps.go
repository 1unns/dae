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

	localIPs, localSubnets := getLocalNetInfo()

	if bpf.DeviceTrafficMap != nil {
		var key [16]byte
		var val bpfTrafficStats
		iter := bpf.DeviceTrafficMap.Iterate()
		count := 0
		for iter.Next(&key, &val) {
			count++
			var ipStr string
			var ip net.IP
			if isIPv4ZeroPrefix(key) {
				ip = net.IPv4(key[12], key[13], key[14], key[15])
			} else {
				ip = net.IP(key[:])
			}
			ipStr = ip.String()
			
			if !isValidDeviceIP(ip, localSubnets) {
				continue
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
			var srcIP, dstIP net.IP
			
			if isIPv4ZeroPrefix(key.Sip.U6Addr8) {
				srcIP = net.IPv4(key.Sip.U6Addr8[12], key.Sip.U6Addr8[13], key.Sip.U6Addr8[14], key.Sip.U6Addr8[15])
			} else {
				srcIP = net.IP(key.Sip.U6Addr8[:])
			}
			srcIpStr = srcIP.String()
			
			if isIPv4ZeroPrefix(key.Dip.U6Addr8) {
				dstIP = net.IPv4(key.Dip.U6Addr8[28-16], key.Dip.U6Addr8[29-16], key.Dip.U6Addr8[30-16], key.Dip.U6Addr8[31-16])
			} else {
				dstIP = net.IP(key.Dip.U6Addr8[:])
			}
			dstIpStr = dstIP.String()

			if !isValidConn(srcIP, dstIP, localIPs, localSubnets) {
				continue
			}

			if bpf.ConnStateMap != nil {
				var state bpfConnState
				err := bpf.ConnStateMap.Lookup(&key, &state)
				if err != nil {
					// Connection state no longer exists, it is closed
					continue
				}
				// State 0 is ESTABLISHED (for TCP). >0 are closing/closed states.
				// UDP always has State 0.
				if state.State > 0 {
					continue
				}
			}

			// Port is in network byte order in bpfTuplesKey?
			// Wait, let's just use binary.BigEndian on a byte slice to be safe if it's network byte order
			dportBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(dportBytes, key.Dport)
			dport := binary.BigEndian.Uint16(dportBytes)
			sportBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(sportBytes, key.Sport)
			sport := binary.BigEndian.Uint16(sportBytes)

			conns = append(conns, ConnTraffic{
				SrcIP:         srcIpStr,
				DstIP:         dstIpStr,
				SrcPort:       sport,
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
func getLocalNetInfo() (map[string]struct{}, []*net.IPNet) {
	localIPs := make(map[string]struct{})
	var subnets []*net.IPNet
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP != nil {
					localIPs[ipnet.IP.String()] = struct{}{}
				}
				subnets = append(subnets, ipnet)
			} else if ipaddr, ok := addr.(*net.IPAddr); ok {
				if ipaddr.IP != nil {
					localIPs[ipaddr.IP.String()] = struct{}{}
				}
			}
		}
	}
	return localIPs, subnets
}

func isValidDeviceIP(ip net.IP, subnets []*net.IPNet) bool {
	if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
		return false
	}
	if ip.String() == "255.255.255.255" {
		return false
	}
	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidConn(srcIP, dstIP net.IP, localIPs map[string]struct{}, subnets []*net.IPNet) bool {
	if dstIP == nil || srcIP == nil {
		return false
	}
	if dstIP.IsMulticast() || dstIP.IsLinkLocalMulticast() || dstIP.IsInterfaceLocalMulticast() || dstIP.IsUnspecified() || dstIP.Equal(net.IPv4bcast) {
		return false
	}
	if srcIP.IsMulticast() || srcIP.IsLinkLocalMulticast() || srcIP.IsInterfaceLocalMulticast() || srcIP.IsUnspecified() || srcIP.Equal(net.IPv4bcast) {
		return false
	}
	if dstIP.String() == "255.255.255.255" || srcIP.String() == "255.255.255.255" {
		return false
	}
	// Hide connections destined to the node itself (e.g. dashboard polling)
	if _, ok := localIPs[dstIP.String()]; ok {
		return false
	}
	// Hide LAN-to-LAN connections
	for _, subnet := range subnets {
		if subnet.Contains(dstIP) {
			return false
		}
	}
	return true
}

func isIPv4ZeroPrefix(ip [16]uint8) bool {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 255 && ip[11] == 255
}
