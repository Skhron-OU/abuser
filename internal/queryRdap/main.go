package queryRdap

import (
	l "abuser/internal/logger"
	"abuser/internal/utils"
	"fmt"
	"net/netip"
	"time"

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

func IpToAbuseC(ip netip.Addr) []string {
	var err error
	var ipMeta *rdap.IPNetwork

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		ipMeta, err = client.QueryIP(ip.String())
		time.Sleep(time.Second * time.Duration(i*2))
	}

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &ipMeta.Entities) // TODO: cache

		if ipMeta.Country == "BR" { // they wish to receive copies of complaints
			abuseContacts["cert@cert.br"] = true
		} else if ipMeta.Country == "IN" {
			abuseContacts["incident@cert-in.org.in"] = true
		}
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", ip.String(), err.Error())
	}

	return utils.Keys(abuseContacts)
}

func AsnToAbuseC(asn string) []string {
	var err error
	var asnMeta *rdap.Autnum

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		asnMeta, err = client.QueryAutnum(asn)
		time.Sleep(time.Second * time.Duration(i*2))
	}

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities)
		// TODO: cache
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts)
}
