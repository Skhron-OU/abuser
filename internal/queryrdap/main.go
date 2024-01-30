package queryrdap

import (
	"abuser/internal/queryerror"
	"abuser/internal/utils"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	l "abuser/internal/logger"

	"github.com/gammazero/deque"
	"github.com/openrdap/rdap"
)

const (
	emailTypeAny   = "*any*"
	emailTypeAbuse = "abuse"

	contactTypeAbuseStrict = "abuseContactAbuseMailbox"
	contactTypeAny         = "abuseMailbox"
	contactTypeAbuseLoose  = "abuseContact"
)

/* FIXME: dead code
var emailRegexp *regexp.Regexp

func init() {
	emailRegexp = regexp.MustCompile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])")
}
*/

func mailboxCollector(abuseContacts *map[string]bool, props []*rdap.VCardProperty, emailType string) {
	var (
		processedEmail string
		isMatchingProp bool
	)

	for _, property := range props {
		if property.Name == "email" && property.Type == "text" {
			isMatchingProp = (emailType == emailTypeAny || utils.Index(property.Parameters["type"], emailType) != -1 || // generic
				(emailType == emailTypeAbuse && utils.Index(property.Parameters["pref"], "1") != -1)) // APNIC specific

			if isMatchingProp {
				processedEmail = fmt.Sprint(property.Value)
				processedEmail = strings.TrimSpace(processedEmail)
				processedEmail = strings.ToLower(processedEmail)
				(*abuseContacts)[processedEmail] = true
			}
		}
	}
}

func processEntity(abuseContacts *map[string]bool, entity *rdap.Entity, links *[]rdap.Link, contactType string) {
	// resolve only bare minimum of contacts
	if len(*abuseContacts) > 0 {
		return
	}

	// They do not wish to hear anything about abuse complaints:
	// "Please note that CNNIC is not an ISP and is not empowered to
	// investigate complaints of network abuse. Please contact the tech-c
	// or admin-c of the network."
	if entity.Handle == "IRT-CNNIC-CN" {
		return
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
					time.Sleep(time.Second * time.Duration(i*5))

					entityResponse, err = client.Do(entityRequest)
					if isClientError(rdap.ObjectDoesNotExist, err) {
						break
					}
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
	}

	// process root Entity
	if entity.VCard != nil {
		switch contactType {
		case contactTypeAbuseStrict:
			/* entity role abuse, lookup abuse-mailbox */
			if utils.Index(entity.Roles, "abuse") != -1 {
				mailboxCollector(abuseContacts, entity.VCard.Properties, emailTypeAbuse)
			}
			break
		case contactTypeAny:
			/* no matter what entity role is, lookup abuse-mailbox */
			mailboxCollector(abuseContacts, entity.VCard.Properties, emailTypeAbuse)
			break
		case contactTypeAbuseLoose:
			/* lookup all emails from entity with role of abuse */
			if utils.Index(entity.Roles, "abuse") != -1 {
				mailboxCollector(abuseContacts, entity.VCard.Properties, emailTypeAny)
			}
			break
		case emailTypeAny:
		default:
			/* fallback mode, gather all available emails */
			/* FIXME: disabled due to triggering Spamhaus DBL
			mailboxCollector(abuseContacts, entity.VCard.Properties, emailTypeAny)
			*/
		}
	}

	// remove invalid contacts
	for _, remark := range entity.Remarks {
		for _, description := range remark.Description {
			// APNIC-specific
			invalidEmail := strings.Replace(description, " is invalid", "", 1)
			if _, ok := (*abuseContacts)[invalidEmail]; ok { // APNIC-specific
				delete((*abuseContacts), invalidEmail)
			}
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity, links *[]rdap.Link) {
	var (
		q      deque.Deque[*rdap.Entity]
		entity *rdap.Entity
	)

	for _, contactType := range []string{contactTypeAbuseStrict, contactTypeAny, contactTypeAbuseLoose, emailTypeAny} {
		if len(*abuseContacts) == 0 {
			for i := range *entities {
				q.PushBack(&(*entities)[i])
			}

			for q.Len() != 0 {
				entity = q.PopFront()
				processEntity(abuseContacts, entity, links, contactType)
				for i := range entity.Entities {
					q.PushBack(&(*&entity.Entities)[i])
				}
			}
		} else {
			break
		}
	}
}

/* FIXME: fallback is unused now, this is a dead code
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
*/

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

	for i := 0; i == 0 || (i < 10 && err != nil); i++ {
		time.Sleep(time.Second * time.Duration(i*5))

		ipMeta, err = client.QueryIP(ip.String())
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryerror.ErrBogonResource
		}
	}

	var abuseContacts = make(map[string]bool, 0)

	if err == nil {
		if ipMeta.Type == "ALLOCATED UNSPECIFIED" {
			return nil, queryerror.ErrBogonResource
		}

		metaProcessor(&abuseContacts, &ipMeta.Entities, &ipMeta.Links)

		// try to extract email from remarks... -_-
		/* FIXME: disabled due to triggering Spamhaus DBL
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &ipMeta.Remarks, &ipMeta.Entities)
		}
		*/

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
		time.Sleep(time.Second * time.Duration(i*5))

		asnMeta, err = client.QueryAutnum(strconv.Itoa(int(asn)))
		if isClientError(rdap.ObjectDoesNotExist, err) {
			return nil, queryerror.ErrBogonResource
		}
	}

	var abuseContacts = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities, &asnMeta.Links)

		// try to extract email from remarks... -_-
		/* FIXME: disabled due to triggering Spamhaus DBL
		if len(abuseContacts) == 0 {
			remarkProcessor(&abuseContacts, &asnMeta.Remarks, &asnMeta.Entities)
		}
		*/
	} else {
		l.Logger.Printf("[%d] RDAP query failed: %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts), nil
}
