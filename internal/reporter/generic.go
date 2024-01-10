package reporter

import (
	"abuser/internal/mail"
	"abuser/internal/utils"
	"abuser/internal/webreport"
	"bytes"
	"net/netip"
	"os"
	"strings"
	"text/template"

	l "abuser/internal/logger"
)

var templateMap map[string]map[string]*template.Template

// TODO: do not hardcode these?
var reportMap = map[string]string{
	"abuse@ovh.ca":  "blackhole", // abuse@ovh.net is present always, no need to report it twice
	"abuse@ovh.net": "web/ovh",
	// temporary disabled, TODO xarf support
	"abuse@digitalocean.com": "blackhole", //"web/digitalocean",
	"noc@digitalocean.com":   "blackhole", //"web/digitalocean",
	// temporary, reach out apnic
	"helpdesk@apnic.net": "blackhole",
	// are ignoring portscan: "We cannot meaningfully process complaints about an IP simply looking at a port."
	"abuse@lightedge.com": "blackhole",
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
					templateMap[categoryName][templateName], _ = template.ParseFiles(templateFilename)
				}
			}
		}
	}
}

func Report(recipientsEmail []string, attacker netip.Addr, details interface{}, category string) {
	buf := &bytes.Buffer{}

	var err error
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

	buf.Reset()
	err = tmplTitle.Execute(buf, details)
	utils.HandleCriticalError(err)
	title = strings.TrimSpace(buf.String())

	buf.Reset()
	err = tmplBody.Execute(buf, details)
	utils.HandleCriticalError(err)
	body = strings.TrimSpace(buf.String())

	var legacyRecipients []string
	for _, recipientEmail := range recipientsEmail {
		reportMethod, prs := reportMap[recipientEmail]
		if prs {
			switch reportMethod {
			case "web/ovh":
				webreport.ToOVH(category, attacker, body, os.Getenv("SMTP_SENDER"))
				break
			case "web/digitalocean":
				webreport.ToDigitalOcean(category, attacker, body, os.Getenv("SMTP_SENDER"))
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

	emailCreds := mail.SMTP{
		Helo: os.Getenv("SMTP_HELO"),
		Host: os.Getenv("SMTP_HOST"),
		User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"),
		Port: 465,
	}

	if len(legacyRecipients) > 0 {
		email := mail.Email{EnvelopeFrom: os.Getenv("SMTP_ENVELOPEFROM")}

		// send abuse complaint only to the legacy recipients
		email.EnvelopeTo = legacyRecipients

		email.Headers = make(map[string]string)
		email.Headers["From"] = os.Getenv("SMTP_SENDER")
		// pretend like we have sent letter to anyone (even blackholed recipients)
		email.Headers["To"] = strings.Join(recipientsEmail, ", ")

		email.Headers["Subject"] = title
		email.Body = body

		email.Send(emailCreds, 0)
	}
}
