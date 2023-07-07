package resolveAbuseC

import (
	"abuser/internal/utils"
	"fmt"
	"log"
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
				break /* only one abuse contact can be attached */
			}
		}
	}
}

func ForIpByRDAP(ip netip.Addr) []string {
	client := &rdap.Client{UserAgent: "SkhronAbuseComplainSender"}
	ipMeta, err := client.QueryIP(ip.String())

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &ipMeta.Entities)
	} else {
		log.Printf("ForIpByRDAP(%s) %s\n", ip.String(), err.Error())
	}

	return utils.Keys(abuseContacts)
}

func ForAsnByRDAP(asn string) []string {
	client := &rdap.Client{UserAgent: "SkhronAbuseComplainSender"}
	asnMeta, err := client.QueryAutnum(asn)

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities)
	} else {
		log.Printf("ForAsnByRDAP(%s) %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts)
}
