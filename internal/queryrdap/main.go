package queryrdap

import (
	"abuser/internal/queryerror"
	"abuser/internal/utils"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	l "abuser/internal/logger"

	"github.com/openrdap/rdap"
)

const typeAny = "*any*"

var emailRegexp *regexp.Regexp

func init() {
	emailRegexp = regexp.MustCompile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])")
}

func mailboxCollector(abuseContacts *map[string]bool, props []*rdap.VCardProperty, emailType string) {
	var processedEmail string
	for _, property := range props {
		if property.Name == "email" && property.Type == "text" {
			if emailType == typeAny || utils.Index(property.Parameters["type"], emailType) != -1 {
				processedEmail = fmt.Sprint(property.Value)
				processedEmail = strings.TrimSpace(processedEmail)
				processedEmail = strings.ToLower(processedEmail)
				(*abuseContacts)[processedEmail] = true
			}
		}
	}
}

func loopEntity(abuseContacts *map[string]bool, entity *rdap.Entity, links *[]rdap.Link, contactType string) {
	// process child Entities if any
	for i := range entity.Entities {
		loopEntity(abuseContacts, &entity.Entities[i], links, contactType)
	}

	var err error
	client := &rdap.Client{}

	// do additional query for this entity if RIR didn't include contact details for some reason
	if entity.VCard == nil && len(*links) > 0 && entity.Handle != "" {
		entityRequest := rdap.NewEntityRequest(entity.Handle)
		for _, link := range *links {
			if link.Rel == "self" {
				entityRequest.Server, err = url.Parse(link.Href)
				entityRequest.Server.Path = ""
				if err != nil {
					break
				}

				var entityResponse *rdap.Response
				for i := 0; i == 0 || (i < 5 && err != nil); i++ {
					entityResponse, err = client.Do(entityRequest)
					if isClientError(rdap.ObjectDoesNotExist, err) {
						break
					}
					time.Sleep(time.Second * time.Duration((i+1)*2))
				}

				entity.VCard = entityResponse.Object.(*rdap.Entity).VCard
				break
			}
		}
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
		switch contactType {
		case "abuseMailbox":
			/* no matter what entity role is, lookup abuse-mailbox */
			mailboxCollector(abuseContacts, entity.VCard.Properties, "abuse")
			break
		case "abuseContact":
			/* lookup all emails from entity with role of abuse */
			if utils.Index(entity.Roles, "abuse") != -1 {
				mailboxCollector(abuseContacts, entity.VCard.Properties, typeAny)
			}
			break
		default:
			/* fallback mode, gather all available emails */
			mailboxCollector(abuseContacts, entity.VCard.Properties, typeAny)
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity, links *[]rdap.Link) {
	for i := range *entities {
		loopEntity(abuseContacts, &(*entities)[i], links, "abuseMailbox")
	}

	for _, contactType := range []string{"abuseContact", typeAny} {
		if len(*abuseContacts) == 0 {
			for i := range *entities {
				loopEntity(abuseContacts, &(*entities)[i], links, contactType)
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
		}
	}

	for i := range *entities {
		remarkProcessor(abuseContacts, &(*entities)[i].Remarks, &(*entities)[i].Entities)
	}
}

func isClientError(t rdap.ClientErrorType, err error) bool {
	var ce rdap.ClientError
	if errors.As(err, &ce) {
		if ce.Type == t {
			return true
		}
	}

	return false
}

func IPAddrToAbuseC(ip netip.Addr) ([]string, error) {
	var err error
	var ipMeta *rdap.IPNetwork

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		ipMeta, err = client.QueryIP(ip.String())
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryerror.ErrBogonResource
		}

		time.Sleep(time.Second * time.Duration((i+1)*2))
	}

	var abuseContacts = make(map[string]bool, 0)

	if err == nil {
		if ipMeta.Type == "ALLOCATED UNSPECIFIED" {
			return nil, queryerror.ErrBogonResource
		}

		metaProcessor(&abuseContacts, &ipMeta.Entities, &ipMeta.Links)

		// try to extract email from remarks... -_-
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &ipMeta.Remarks, &ipMeta.Entities)
		}

		if ipMeta.Country == "BR" { // they wish to receive copies of complaints
			abuseContacts["cert@cert.br"] = true
		}
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", ip.String(), err.Error())
	}

	return utils.Keys(abuseContacts), nil
}

func AsnToAbuseC(asn uint) ([]string, error) {
	var err error
	var asnMeta *rdap.Autnum

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	for i := 0; i == 0 || (i < 5 && err != nil); i++ {
		asnMeta, err = client.QueryAutnum(strconv.Itoa(int(asn)))
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryerror.ErrBogonResource
		}

		time.Sleep(time.Second * time.Duration(i*2))
	}

	var abuseContacts = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities, &asnMeta.Links)

		// try to extract email from remarks... -_-
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &asnMeta.Remarks, &asnMeta.Entities)
		}
	} else {
		l.Logger.Printf("[%d] RDAP query failed: %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts), nil
}
