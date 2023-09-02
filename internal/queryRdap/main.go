package queryRdap

import (
	l "abuser/internal/logger"
	"abuser/internal/queryError"
	"abuser/internal/utils"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/openrdap/rdap"
)

const typeAny = "*any*"

var emailRegexp *regexp.Regexp

func init() {
	emailRegexp = regexp.MustCompile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])")
}

func mailboxCollector(abuseContacts *map[string]bool, props []*rdap.VCardProperty, emailType string) {
	for _, property := range props {
		if property.Name == "email" && property.Type == "text" {
			if emailType == typeAny || utils.Index(property.Parameters["type"], emailType) != -1 {
				(*abuseContacts)[strings.ToLower(fmt.Sprint(property.Value))] = true
			}
		}
	}
}

func loopEntity(abuseContacts *map[string]bool, entity *rdap.Entity, contactType string) {
	// process child Entities if any
	for _, entityChild := range entity.Entities {
		loopEntity(abuseContacts, &entityChild, contactType)
	}

	// skip invalid contacts
	for _, remark := range entity.Remarks {
		if remark.Title == "Unvalidated POC" { // ARIN-specific
			return
		}

		for _, description := range remark.Description {
			if strings.HasSuffix(description, " is invalid") { // APNIC-specific
				return
			} else if description == "Please contact the tech-c or admin-c of the network." { // CNNIC warning
				return
			}
		}
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
			mailboxCollector(abuseContacts, entity.VCard.Properties, typeAny)
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity) {
	for _, entity := range *entities {
		loopEntity(abuseContacts, &entity, "abuseMailbox")
	}

	for _, contactType := range []string{"abuseContact", typeAny} {
		if len(*abuseContacts) == 0 {
			for _, entity := range *entities {
				loopEntity(abuseContacts, &entity, contactType)
			}
		} else {
			break
		}
	}
}

func remarkProcessor(abuseContacts *map[string]bool, remarks *[]rdap.Remark, entities *[]rdap.Entity) {
	var emails []string
	for _, remark := range *remarks {
		for _, description := range remark.Description {
			emails = emailRegexp.FindAllString(description, -1)
			for _, email := range emails {
				(*abuseContacts)[email] = true
			}
			emails = nil
		}
	}

	for _, entity := range *entities {
		remarkProcessor(abuseContacts, &entity.Remarks, &entity.Entities)
	}
}

// copied from openrdap/rdap/client_error.go...
func isClientError(t rdap.ClientErrorType, err error) bool {
	if ce, ok := err.(*rdap.ClientError); ok {
		if ce.Type == t {
			return true
		}
	}

	return false
}

func IpToAbuseC(ip netip.Addr) ([]string, error) {
	var err error
	var ipMeta *rdap.IPNetwork

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		ipMeta, err = client.QueryIP(ip.String())
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryError.BogonResource
		}

		time.Sleep(time.Second * time.Duration(i*2))
	}

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		if ipMeta.Type == "ALLOCATED UNSPECIFIED" {
			return nil, queryError.BogonResource
		}

		metaProcessor(&abuseContacts, &ipMeta.Entities)

		// try to extract email from remarks... -_-
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &ipMeta.Remarks, &ipMeta.Entities)
		}

		if ipMeta.Country == "BR" { // they wish to receive copies of complaints
			abuseContacts["cert@cert.br"] = true
		} else if ipMeta.Country == "IN" {
			abuseContacts["incident@cert-in.org.in"] = true
		}
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", ip.String(), err.Error())
	}

	return utils.Keys(abuseContacts), nil
}

func AsnToAbuseC(asn string) ([]string, error) {
	var err error
	var asnMeta *rdap.Autnum

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		asnMeta, err = client.QueryAutnum(asn)
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryError.BogonResource
		}

		time.Sleep(time.Second * time.Duration(i*2))
	}

	var abuseContacts map[string]bool = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities)

		// try to extract email from remarks... -_-
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &asnMeta.Remarks, &asnMeta.Entities)
		}
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts), nil
}
