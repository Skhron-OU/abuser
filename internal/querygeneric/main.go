package querygeneric

import (
	"abuser/internal/queryerror"
	"abuser/internal/queryrdap"
	"abuser/internal/queryripestat"
	"abuser/internal/utils"
	"errors"
	"net/netip"
)

type BogonStatus struct {
	IsBogonIP  bool
	HasValidAS bool
	BogonsAS   []uint
}

// TODO: generate clarification why specific email address was added to further
// embed this explanation into the abuse letter
func IPAddrToAbuseC(ip netip.Addr) ([]string, BogonStatus) {
	var bogonStatus = BogonStatus{BogonsAS: make([]uint, 0)}

	emails, err := queryrdap.IPAddrToAbuseC(ip)

	if errors.Is(err, queryerror.ErrBogonResource) {
		bogonStatus.IsBogonIP = true
	}

	var asns []uint = queryripestat.IPAddrToAS(ip)
	bogonStatus.HasValidAS = (len(asns) > 0)

	// fallback
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

	// remove duplicates
	return utils.GetUnique(emails), bogonStatus
}
