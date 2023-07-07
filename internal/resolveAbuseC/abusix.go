package resolveAbuseC

import (
	"abuser/internal/utils"
	"log"
	"net"
	"strings"
)

func (o *RIRObject) ResolveAbuseContactByAbusix() []string {
	octets := strings.Split(o.Resource, ".")
	if len(octets) != 4 {
		log.Printf("unsupported resource was given: %s\n", o.Resource)
		return nil
	}
	utils.Reverse(octets)

	contacts, _ := net.LookupTXT(strings.Join(octets, ".") + ".abuse-contacts.abusix.zone.")

	if len(contacts) == 0 { /* fallback */
		contacts = append(contacts, "abuse+contact-not-found@skhron.com.ua")
	}

	return contacts
}
