package reporter

import (
	"abuser/internal/mail"
	"abuser/internal/structs"
	"abuser/internal/utils"
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	l "abuser/internal/logger"
)

type digitaloceanDetails[T any] struct {
	FromEmail string
	Evidence  string
	IP        string
	Date      string
	Time      string
	Events    []T
}

var templateMap map[string]map[string]*template.Template

// TODO: do not hardcode these?
var reportMap = map[string]string{
	"noc@ovh.net":   "web/ovh",
	"abuse@ovh.net": "web/ovh",
	"abuse@ovh.ca":  "web/ovh",
	// TODO: develop XARF to remove this quirk
	"abuse@digitalocean.com": "email/digitalocean",
}

func init() {
	templateMap = make(map[string]map[string]*template.Template)

	var categoryName, templateName string

	baseDir := "assets/templates/"
	categories, err := os.ReadDir(baseDir)
	utils.HandleCriticalError(err)
	for _, categoryEntry := range categories {
		if categoryEntry.IsDir() {
			categoryName = categoryEntry.Name()
			templateMap[categoryName] = make(map[string]*template.Template)

			templates, err := os.ReadDir(baseDir + categoryName)
			utils.HandleCriticalError(err)
			for _, templateFile := range templates {
				templateName = strings.ReplaceAll(templateFile.Name(), ".tmpl", "")

				if !templateFile.IsDir() {
					templateFilename := baseDir + categoryName + "/" + templateFile.Name()
					templateMap[categoryName][templateName], _ = template.New(templateFile.Name()).Funcs(template.FuncMap{
						"urlpathescape": func(s string) string {
							return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
						},
						"repeat": strings.Repeat,
						"sum":    utils.Sum[int],
					}).ParseFiles(templateFilename)
				}
			}
		}
	}
}

func renderTemplate(tmpl *template.Template, data interface{}) string {
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, data)
	utils.HandleCriticalError(err)
	return strings.TrimSpace(buf.String())
}

func Report[T any](recipientsEmail []string, attacker netip.Addr, data structs.TemplateData[T], category string) {
	var title, body string

	tmplMap, prs := templateMap[category]
	if !prs {
		l.Logger.Printf("Category %s is not available\n", category)
		return
	}

	tmplTitle, prs := tmplMap["subject"]
	if !prs {
		l.Logger.Printf("No title template present for %s category\n", category)
		return
	}

	tmplBody, prs := tmplMap["body"]
	if !prs {
		l.Logger.Printf("No body template present for %s category\n", category)
		return
	}

	title = renderTemplate(tmplTitle, data)
	body = renderTemplate(tmplBody, data)

	emailCreds := mail.SMTP{
		Helo: os.Getenv("SMTP_HELO"),
		Host: os.Getenv("SMTP_HOST"),
		User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"),
		Port: 465,
	}

	tmplAddrReplyTo, _ := template.New("").Parse(os.Getenv("SMTP_REPLYTO_TMPL"))
	addrReplyToHeader := renderTemplate(tmplAddrReplyTo, struct{ HexID string }{HexID: utils.HexIpAddr(attacker)})
	addrFromHeader, addrFromEnvelope := os.Getenv("SMTP_SENDER"), os.Getenv("SMTP_ENVELOPEFROM")

	var legacyRecipients []string
	for _, recipientEmail := range recipientsEmail {
		reportMethod, prs := reportMap[recipientEmail]
		if prs {
			switch reportMethod {
			case "web/ovh":
				ToOVH(category, attacker, body, addrReplyToHeader)
				break
			// FIXME: "Don't repeat yourself"
			case "email/digitalocean":
				tmplCustomBody, prs := tmplMap["body.digitalocean"]
				if !prs {
					l.Logger.Printf("No digitalocean specific body template present for %s category\n", category)
					continue
				}

				email := mail.Email{
					EnvelopeFrom: addrFromEnvelope,
					EnvelopeTo:   []string{recipientEmail},
					Headers:      make(map[string]string),
				}

				email.Headers["From"] = addrFromHeader
				email.Headers["Reply-To"] = addrReplyToHeader
				email.Headers["To"] = recipientEmail
				email.Headers["Subject"] = title

				now := time.Now().UTC()
				customDetails := digitaloceanDetails[T]{
					FromEmail: email.Headers["From"],
					Evidence:  body,
					IP:        attacker.String(),
					Date:      fmt.Sprintf("%d-%02d-%02d", now.Year(), now.Month(), now.Day()),
					Time:      fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute()),
					Events:    data.Events,
				}
				email.Body = renderTemplate(tmplCustomBody, customDetails)

				email.Send(emailCreds, 0)
				break
			case "blackhole":
			default:
				// just skip the blackholed address
				break
			}
		} else {
			// they will receive email letter
			legacyRecipients = append(legacyRecipients, recipientEmail)
		}
	}

	if len(legacyRecipients) > 0 {
		email := mail.Email{EnvelopeFrom: addrFromEnvelope}

		// send abuse complaint only to the legacy recipients
		email.EnvelopeTo = legacyRecipients

		email.Headers = make(map[string]string)
		email.Headers["From"] = addrFromHeader
		// Force abuse complaint recipient to identify reported attacker
		email.Headers["Reply-To"] = addrReplyToHeader
		// pretend like we have sent letter to anyone (even blackholed recipients)
		email.Headers["To"] = strings.Join(recipientsEmail, ", ")

		// RFC 1766
		email.Headers["Content-Language"] = "en" /* FIXME: user provided templates */

		// RFC 3834
		email.Headers["Auto-Submitted"] = "auto-generated"

		email.Headers["Subject"] = title
		email.Body = body

		email.Send(emailCreds, 0)
	}
}
