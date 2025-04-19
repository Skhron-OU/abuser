package querygeneric

import (
	"abuser/internal/queryrdap"
	"abuser/internal/utils"
	"net/netip"
)

// TODO: generate clarification why specific email address was added to further
// embed this explanation into the abuse letter
func IPAddrToAbuseC(ip netip.Addr) []string {
	emails := queryrdap.IPAddrToAbuseC(ip)

	/* FIXME: fallback gets incorrect abuse-mailbox sometimes
	if len(emails) == 0 {
		for _, asn := range asns {
			asnEmails, err := queryrdap.AsnToAbuseC(asn)
			if err == nil {
				emails = append(emails, asnEmails...)
			} else if errors.Is(err, queryerror.ErrBogonResource) {
				bogonStatus.BogonsAS = append(bogonStatus.BogonsAS, asn)
			}
		}
	}
	*/

	// remove duplicates
	return utils.GetUnique(emails)
}
