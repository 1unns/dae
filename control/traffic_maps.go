/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math/bits"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type trafficCache struct {
	sync.Mutex
	lastRead time.Time
	devices  []DeviceTraffic
	conns    []ConnTraffic
}

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

	c.trafficCache.Lock()
	defer c.trafficCache.Unlock()

	if time.Since(c.trafficCache.lastRead) < 1*time.Second && c.trafficCache.devices != nil {
		devices = make([]DeviceTraffic, len(c.trafficCache.devices))
		copy(devices, c.trafficCache.devices)
		conns = make([]ConnTraffic, len(c.trafficCache.conns))
		copy(conns, c.trafficCache.conns)
		return devices, conns
	}

	localIPs, localSubnets := getLocalNetInfo()

	if bpf.DeviceTrafficMap != nil {
		var key [16]byte
		var val bpfTrafficStats
		iter := bpf.DeviceTrafficMap.Iterate()
		for iter.Next(&key, &val) {
			var ip net.IP
			if isIPv4ZeroPrefix(key) {
				ip = net.IPv4(key[12], key[13], key[14], key[15])
			} else {
				ip = net.IP(key[:])
			}
			
			if !isValidDeviceIP(ip, localSubnets) {
				continue
			}

			devices = append(devices, DeviceTraffic{
				IP:                  ip.String(),
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
		for iter.Next(&key, &val) {
			var srcIP, dstIP net.IP
			
			if isIPv4ZeroPrefix(key.Sip.U6Addr8) {
				srcIP = net.IPv4(key.Sip.U6Addr8[12], key.Sip.U6Addr8[13], key.Sip.U6Addr8[14], key.Sip.U6Addr8[15])
			} else {
				srcIP = net.IP(key.Sip.U6Addr8[:])
			}
			
			if isIPv4ZeroPrefix(key.Dip.U6Addr8) {
				dstIP = net.IPv4(key.Dip.U6Addr8[12], key.Dip.U6Addr8[13], key.Dip.U6Addr8[14], key.Dip.U6Addr8[15])
			} else {
				dstIP = net.IP(key.Dip.U6Addr8[:])
			}

			if !isValidConn(srcIP, dstIP, localIPs, localSubnets) {
				continue
			}

			sport := bits.ReverseBytes16(key.Sport)
			dport := bits.ReverseBytes16(key.Dport)

			conns = append(conns, ConnTraffic{
				SrcIP:               srcIP.String(),
				DstIP:               dstIP.String(),
				SrcPort:             sport,
				DstPort:             dport,
				ProxyUploadTotal:    val.ProxyUploadTotal,
				ProxyDownloadTotal:  val.ProxyDownloadTotal,
				DirectUploadTotal:   val.DirectUploadTotal,
				DirectDownloadTotal: val.DirectDownloadTotal,
				UploadTotal:         val.ProxyUploadTotal + val.DirectUploadTotal,
				DownloadTotal:       val.ProxyDownloadTotal + val.DirectDownloadTotal,
			})
		}
		if err := iter.Err(); err != nil {
			logrus.Errorf("ConnTrafficMap Iterate error: %v", err)
		}
	}

	sort.Slice(conns, func(i, j int) bool {
		totalI := conns[i].UploadTotal + conns[i].DownloadTotal
		totalJ := conns[j].UploadTotal + conns[j].DownloadTotal
		return totalI > totalJ
	})
	if len(conns) > 200 {
		conns = conns[:200]
	}

	c.trafficCache.lastRead = time.Now()
	c.trafficCache.devices = make([]DeviceTraffic, len(devices))
	copy(c.trafficCache.devices, devices)
	c.trafficCache.conns = make([]ConnTraffic, len(conns))
	copy(c.trafficCache.conns, conns)

	return devices, conns
}

// ClearTrafficMaps clears the traffic statistics eBPF maps and resets runtime traffic stats.
func (c *ControlPlane) ClearTrafficMaps() error {
	if c == nil {
		return nil
	}
	c.ResetRuntimeStats()
	if c.core == nil {
		return nil
	}
	return c.core.ClearTrafficMaps()
}

func (c *controlPlaneCore) ClearTrafficMaps() error {
	if c == nil {
		return nil
	}

	c.trafficCache.Lock()
	c.trafficCache.devices = nil
	c.trafficCache.conns = nil
	c.trafficCache.lastRead = time.Time{}
	c.trafficCache.Unlock()

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


var (
	cachedLocalNetLock sync.RWMutex
	cachedLocalIPs     map[string]struct{}
	cachedLocalSubnets []*net.IPNet
	cachedLocalNetTime time.Time
)

// getLocalNetInfo returns cached local IP addresses and subnets, refreshed every 30 seconds.
func getLocalNetInfo() (map[string]struct{}, []*net.IPNet) {
	cachedLocalNetLock.RLock()
	if time.Since(cachedLocalNetTime) < 30*time.Second && cachedLocalIPs != nil {
		ips := cachedLocalIPs
		subnets := cachedLocalSubnets
		cachedLocalNetLock.RUnlock()
		return ips, subnets
	}
	cachedLocalNetLock.RUnlock()

	cachedLocalNetLock.Lock()
	defer cachedLocalNetLock.Unlock()

	if time.Since(cachedLocalNetTime) < 30*time.Second && cachedLocalIPs != nil {
		return cachedLocalIPs, cachedLocalSubnets
	}

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
	cachedLocalIPs = localIPs
	cachedLocalSubnets = subnets
	cachedLocalNetTime = time.Now()
	return localIPs, subnets
}

func isValidDeviceIP(ip net.IP, subnets []*net.IPNet) bool {
	if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
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
	if !isValidDeviceIP(srcIP, subnets) {
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
