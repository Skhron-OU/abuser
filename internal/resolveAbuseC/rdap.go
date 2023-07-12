package resolveAbuseC

import (
	"abuser/internal/utils"
	"fmt"
	"log"
	"net/netip"

	"github.com/openrdap/rdap"
)

const typeAny = "*any*"

func mailboxCollector(abuseContacts *map[string]bool, props []*rdap.VCardProperty, emailType string) {
	for _, property := range props {
		if property.Name == "email" && property.Type == "text" {
			if emailType == typeAny || utils.Index(property.Parameters["type"], emailType) != -1 {
				(*abuseContacts)[fmt.Sprint(property.Value)] = true
			}
		}
	}
}

func loopEntity(abuseContacts *map[string]bool, entity *rdap.Entity, contactType string) {
	var emailType string

	// process child Entities if any
	for _, entityChild := range entity.Entities {
		loopEntity(abuseContacts, &entityChild, contactType)
	}

	// process root Entity
	if entity.VCard != nil {
		if contactType == "abuseMailbox" { /* no matter what entity role is, lookup abuse-mailbox */
			mailboxCollector(abuseContacts, entity.VCard.Properties, "abuse")
		} else if contactType == "abuseContact" { /* lookup all emails from entity with role of abuse */
			if utils.Index(entity.Roles, "abuse") != -1 {
				mailboxCollector(abuseContacts, entity.VCard.Properties, typeAny)
			}
		} else { /* fallback mode, gather all available emails */
			emailType = typeAny
			mailboxCollector(abuseContacts, entity.VCard.Properties, emailType)
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity) {
	for _, entity := range *entities {
		loopEntity(abuseContacts, &entity, "abuseMailbox")
	}

	if len(*abuseContacts) == 0 {
		for _, entity := range *entities {
			loopEntity(abuseContacts, &entity, "abuseContact")
		}
	}

	if len(*abuseContacts) == 0 {
		for _, entity := range *entities {
			loopEntity(abuseContacts, &entity, typeAny)
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
