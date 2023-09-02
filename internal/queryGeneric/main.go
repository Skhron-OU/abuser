package queryGeneric

import (
	"abuser/internal/queryError"
	"abuser/internal/queryRdap"
	"abuser/internal/queryRipeStat"
	"abuser/internal/utils"
	"net/netip"
)

type BogonStatus struct {
	IsIpBogon   bool
	IsNoValidAs bool
	BogonAs     []string
}

// TODO: generate clarification why specific email address was added to further
// embed this explanation into the abuse letter
func IpToAbuseC(ip netip.Addr) ([]string, BogonStatus) {
	var bogonStatus BogonStatus = BogonStatus{BogonAs: make([]string, 0)}

	emails, err := queryRdap.IpToAbuseC(ip)
	bogonStatus.IsIpBogon = (err == queryError.BogonResource)

	var asns []string = queryRipeStat.IpToAsn(ip)
	bogonStatus.IsNoValidAs = (len(asns) == 0)

	for _, asn := range asns {
		asnEmails, err := queryRdap.AsnToAbuseC(asn)
		if err == nil {
			emails = append(emails, asnEmails...)
		} else if err == queryError.BogonResource {
			bogonStatus.BogonAs = append(bogonStatus.BogonAs, asn)
		}
	}

	// remove duplicates
	return utils.GetUnique(emails), bogonStatus
}
