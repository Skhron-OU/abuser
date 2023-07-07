package resolveAbuseC

import (
	"abuser/internal/utils"
	"fmt"
	"net/netip"

	"github.com/openrdap/rdap"
)

func mailboxCollector(abuseContacts *map[string]bool, props []*rdap.VCardProperty) {
	for _, property := range props {
		if property.Name == "email" && property.Type == "text" {
			(*abuseContacts)[fmt.Sprint(property.Value)] = true
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity) {
	for _, entity := range *entities {
		if utils.Index(entity.Roles, "abuse") != -1 {
			mailboxCollector(abuseContacts, entity.VCard.Properties)
			break /* only one abuse contact can be attached */
		}
		for _, entityChild := range entity.Entities {
			if utils.Index(entityChild.Roles, "abuse") != -1 {
				mailboxCollector(abuseContacts, entityChild.VCard.Properties)
			}
		}
	}

	/* fallback: if there is no abuse-mailbox available, then return available emails */
	if len(*abuseContacts) == 0 {
		for _, entity := range *entities {
			mailboxCollector(abuseContacts, entity.VCard.Properties)
			for _, entityChild := range entity.Entities {
				mailboxCollector(abuseContacts, entityChild.VCard.Properties)
			}
		}
	}
}

func ForIpByRDAP(ip netip.Addr) []string {
	client := &rdap.Client{}
	ipMeta, _ := client.QueryIP(ip.String())

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	metaProcessor(&abuseContacts, &ipMeta.Entities)

	return utils.Keys(abuseContacts)
}

func ForAsnByRDAP(asn string) []string {
	client := &rdap.Client{}
	asnMeta, _ := client.QueryAutnum(asn)

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	metaProcessor(&abuseContacts, &asnMeta.Entities)

	return utils.Keys(abuseContacts)
}
