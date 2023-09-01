package queryGeneric

import (
	"abuser/internal/queryAbusix"
	"abuser/internal/queryRdap"
	"abuser/internal/queryRipeStat"
	"abuser/internal/utils"
	"net/netip"
)

// TODO: generate clarification why specific email address was added to further
// embed this explanation into the abuse letter
// TODO: handle bogons: either IP/ASN or both
func IpToAbuseC(ip netip.Addr) []string {
	var abuseContacts []string = queryRdap.IpToAbuseC(ip)

	for _, asn := range queryRipeStat.IpToAsn(ip) {
		abuseContacts = append(abuseContacts, queryRdap.AsnToAbuseC(asn)...)
	}

	if len(abuseContacts) == 0 { /* generic fallback, available for IPv4 only */
		abuseContacts = queryAbusix.IpToAbuseC(ip)
	}

	// remove duplicates
	return utils.GetUnique(abuseContacts)
}
