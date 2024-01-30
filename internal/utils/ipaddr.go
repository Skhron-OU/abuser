package utils

import "net/netip"

func NormalizeIpAddr(ip string) netip.Addr {
	rawAddr := netip.MustParseAddr(ip)

	if rawAddr.Is6() {
		raw6 := rawAddr.As16()

		// RFC3056: 6to4
		top16 := uint16(raw6[0])<<8 | uint16(raw6[1])
		fp, tla := top16>>13, top16&0x1FFF
		if fp == 0b001 && tla == 0x0002 {
			raw4 := *(*[4]byte)(raw6[2:6])

			rawAddr = netip.AddrFrom4(raw4)
		}
	}

	return rawAddr
}
