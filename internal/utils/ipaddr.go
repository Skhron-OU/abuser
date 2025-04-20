package utils

import (
	"encoding/hex"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

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

// Convert IP range to a format of ipaddress/mask
// On error, empty string is returned
func NormalizeIpRange(ipr string) string {
	var err error
	var rString []string
	var rStartA, rEndA netip.Addr
	var rStartB, rEndB []byte
	var rPrefix netip.Prefix
	var mask = 0
	var maskDiff float64
	if strings.Contains(ipr, " - ") {
		if rString = strings.Split(ipr, " - "); len(rString) != 2 {
			return ""
		}

		if rStartA, err = netip.ParseAddr(rString[0]); err != nil {
			return ""
		}

		rEndA, err = netip.ParseAddr(rString[1])
		if err != nil || rStartA.BitLen() != rEndA.BitLen() {
			return ""
		}

		rStartB = rStartA.AsSlice()
		rEndB = rEndA.AsSlice()
		var index, diff int
		for b := rStartA.BitLen(); b > 0; b -= 8 {
			index = (b / 8) - 1
			diff = int(rEndB[index]) - int(rStartB[index])
			if diff >= 0 {
				maskDiff = math.Log2(float64(diff + 1))
				if maskDiff != math.Trunc(maskDiff) {
					return ""
				} else {
					mask += int(maskDiff)
				}
			} else {
				return ""
			}
		}

		mask = rStartA.BitLen() - mask
		if rPrefix, err = rStartA.Prefix(mask); err != nil {
			return ""
		} else {
			return rPrefix.String()
		}
	} else if strings.Contains(ipr, "/") {
		if rString = strings.Split(ipr, "/"); len(rString) != 2 {
			return ""
		}

		if rStartA, err = netip.ParseAddr(rString[0]); err != nil {
			return ""
		}

		if mask, err = strconv.Atoi(rString[1]); err != nil {
			return ""
		}

		if rPrefix, err = rStartA.Prefix(mask); err != nil {
			return ""
		} else {
			return rPrefix.String()
		}
	}

	return ""
}

func HexIpAddr(ip netip.Addr) string {
	return hex.EncodeToString(ip.AsSlice())
}
