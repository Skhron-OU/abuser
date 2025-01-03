package querygeneric

import (
	"abuser/internal/queryerror"
	"abuser/internal/queryrdap"
	"abuser/internal/utils"
	"errors"
	"net/netip"
)

type BogonStatus struct {
	IsBogonIP bool
}

// TODO: generate clarification why specific email address was added to further
// embed this explanation into the abuse letter
func IPAddrToAbuseC(ip netip.Addr) ([]string, BogonStatus) {
	var bogonStatus = BogonStatus{}

	emails, err := queryrdap.IPAddrToAbuseC(ip)

	if errors.Is(err, queryerror.ErrBogonResource) {
		bogonStatus.IsBogonIP = true
	}

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
	return utils.GetUnique(emails), bogonStatus
}
