package queryAbusix

import (
	"abuser/internal/utils"
	"log"
	"net"
	"net/netip"
	"strings"
)

func IpToAbuseC(ip netip.Addr) []string {
	octets := strings.Split(ip.String(), ".")
	if len(octets) != 4 {
		log.Printf("unsupported resource was given: %s\n", ip.String())
		return nil
	}
	utils.Reverse(octets)

	contacts, _ := net.LookupTXT(strings.Join(octets, ".") + ".abuse-contacts.abusix.zone.")

	if len(contacts) == 0 { /* fallback */
		return []string{"abuse+contact-not-found@skhron.com.ua"}
	}

	return contacts
}
