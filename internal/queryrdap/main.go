package queryrdap

import (
	"abuser/internal/utils"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

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

var nichdlForceValid map[string]bool
var nichdlOptOut map[string]bool

func nichdl(nichdlMap *map[string]bool, nichdlPath string) {
	f, err := os.Open(nichdlPath)

	if err != nil {
		l.Logger.Printf("%s\n", err.Error())
		return
	}

	defer f.Close()

	b, err := io.ReadAll(f)

	for _, entry := range bytes.Split(b, []byte("\n")) {
		entry = bytes.TrimSpace(entry)

		if len(entry) == 0 || bytes.HasPrefix(entry, []byte("#")) {
			continue
		}

		(*nichdlMap)[*(*string)(unsafe.Pointer(&entry))] = true
	}
}

func init() {
	nichdlForceValid = make(map[string]bool, 0)
	nichdl(&nichdlForceValid, "assets/rir/nic-hdl_force_valid.txt")

	nichdlOptOut = make(map[string]bool, 0)
	nichdl(&nichdlOptOut, "assets/rir/nic-hdl_optout.txt")
}

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

func processEntity(abuseContacts *map[string]bool, entity *rdap.Entity, contactType string) {
	// resolve only bare minimum of contacts
	if len(*abuseContacts) > 0 {
		return
	}

	// opt out specific contacts
	if _, ok := nichdlOptOut[entity.Handle]; ok {
		return
	}

	client := &rdap.Client{}

	// do additional query for this entity if RIR didn't include contact details for some reason
	if entity.VCard == nil && entity.Handle != "" {
	EntityLinksLoop:
		for _, link := range entity.Links {
			if link.Rel == "self" {
				entityUrl, err := url.Parse(link.Href)
				if err != nil {
					break
				}

				entityRequest := rdap.NewRawRequest(entityUrl)

				entityResponse, retriesDone := (*rdap.Response)(nil), 0
				for ; retriesDone == 0 || (retriesDone < 10 && err != nil); retriesDone++ {
					time.Sleep(time.Second * time.Duration(retriesDone*5))

					entityResponse, err = client.Do(entityRequest)
					if err != nil && isClientError(rdap.ObjectDoesNotExist, err) {
						l.Logger.Printf("%s", entityResponse.Object.(*rdap.Entity).DecodeData.String())
						break EntityLinksLoop
					}
				}

				if err != nil || entityResponse == nil {
					l.Logger.Printf("[%s] RDAP query failed: no entity data found after %d tries because %s", entity.Handle, retriesDone, err.Error())
					break
				}

				entity.VCard = entityResponse.Object.(*rdap.Entity).VCard
				break
			}
		}
	}

	// skip invalid contacts
	if _, ok := nichdlForceValid[entity.Handle]; !ok {
		for _, remark := range entity.Remarks {
			if remark.Title == "Unvalidated POC" { // ARIN-specific
				return
			}
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
		}
	}

	for _, field := range entity.DecodeData.Fields() {
		notes := entity.DecodeData.Notes(field)
		if len(notes) > 0 {
			l.Logger.Printf("[%s] Minor RDAP query warnings/errors: %+v", entity.Handle, notes)
		}
	}

	// remove invalid contacts
	if _, ok := nichdlForceValid[entity.Handle]; !ok {
		for _, remark := range entity.Remarks {
			for _, description := range remark.Description {
				// APNIC-specific
				invalidEmail := strings.Replace(description, " is invalid", "", 1)

				if invalidEmail == description {
					continue
				}

				if _, ok := (*abuseContacts)[invalidEmail]; ok {
					delete((*abuseContacts), invalidEmail)
				}
			}
		}
	}
}

func metaProcessor(abuseContacts *map[string]bool, entities *[]rdap.Entity) {
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
				processEntity(abuseContacts, entity, contactType)
				for i := range entity.Entities {
					q.PushBack(&(*&entity.Entities)[i])
				}
			}
		} else {
			break
		}
	}
}

func isClientError(t rdap.ClientErrorType, err error) bool {
	if ce, ok := err.(*rdap.ClientError); ok {
		if ce.Type == t {
			return true
		}
	}

	return false
}

func IPAddrToAbuseC(ipAddr netip.Addr) []string {
	var err error
	var ipStr string = ipAddr.String()
	var ipMeta *rdap.IPNetwork
	var abuseContacts = make(map[string]bool, 0)

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

RecurseIPAddrToAbuseC:
	retriesDone := 0
	for ; retriesDone == 0 || (retriesDone < 10 && err != nil); retriesDone++ {
		time.Sleep(time.Second * time.Duration(retriesDone*5))

		ipMeta, err = client.QueryIP(ipStr)
		if err != nil &&
			(isClientError(rdap.ObjectDoesNotExist, err) ||
			isClientError(rdap.BootstrapNoMatch, err)) {
			return nil
		}
	}

	if err == nil {
		// FIXME: afrinic rdap does not return abuse-mailbox even if it
		// is present, possible workaround is to query and parse whois
		// instead
		if ipMeta.Port43 == "whois.afrinic.net" {
			return nil
		}

		if ipMeta.Type == "ALLOCATED UNSPECIFIED" || ipMeta.Type == "ALLOCATED-BY-RIR" {
			return nil
		}

		metaProcessor(&abuseContacts, &ipMeta.Entities)

		if len(abuseContacts) == 0 {
			if retriesDone > 1 {
				l.Logger.Printf("[%s] RDAP query failed: no abuse contacts found after %d tries\n", ipStr, retriesDone)
			}

			if ipMeta.ParentHandle != "" {
				ipStr = utils.NormalizeIpRange(ipMeta.ParentHandle)
				if ipStr != "" {
					goto RecurseIPAddrToAbuseC
				}

				// TODO: ARIN returns ParentHandle
				// NET-x-x-x-x-x, alternate parent query method
				// can be considered
			}
		} else {
			if ipMeta.Country == "BR" { // they wish to receive copies of complaints
				abuseContacts["cert@cert.br"] = true
			}
		}
	} else {
		l.Logger.Printf("[%s] RDAP query failed: %s\n", ipStr, err.Error())
	}

	return utils.Keys(abuseContacts)
}

func AsnToAbuseC(asn uint) []string {
	var err error
	var asnMeta *rdap.Autnum

	client := &rdap.Client{UserAgent: "SkhronAbuseComplaintSender"}

	retriesDone := 0
	for ; retriesDone == 0 || (retriesDone < 10 && err != nil); retriesDone++ {
		time.Sleep(time.Second * time.Duration(retriesDone*5))

		asnMeta, err = client.QueryAutnum(strconv.Itoa(int(asn)))
		if err != nil && isClientError(rdap.ObjectDoesNotExist, err) {
			return nil
		}
	}

	var abuseContacts = make(map[string]bool, 0)

	if err == nil {
		metaProcessor(&abuseContacts, &asnMeta.Entities)

		if len(abuseContacts) == 0 {
			l.Logger.Printf("[%d] RDAP query failed: no abuse contacts found after %d tries\n", asn, retriesDone)
		}
	} else {
		l.Logger.Printf("[%d] RDAP query failed: %s\n", asn, err.Error())
	}

	return utils.Keys(abuseContacts)
}
