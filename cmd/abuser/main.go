package main

import (
	"abuser/internal/mail"
	"abuser/internal/resolveAbuseC"
	"abuser/internal/utils"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
)

var tmpl_portscan_subject, tmpl_portscan_body *template.Template

// TODO: reply early, process parsedBody in a separate goroutine

type __portscan_event struct {
	SrcIp     string // compatibility with Body template
	SrcPort   uint16
	DstIp     string
	DstPort   uint16
	Timestamp string
}

type tmplvar_portscan struct {
	Ip     string // compatibility with Subject template
	Events []__portscan_event
}

type crowdsecEvent struct {
	Meta      []crowdsecEventMeta `json:"meta"`
	Timestamp string              `json:"timestamp"`
}

type crowdsecEventMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type crowdsecSource struct {
	ASN string `json:"as_number"`
	Ip  string `json:"ip"`
}

type WebhookCrowdsec struct {
	Events []crowdsecEvent `json:"events"`
	Source crowdsecSource  `json:"source"`
}

func webhookCrowdsec(w http.ResponseWriter, r *http.Request) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	utils.HandleCriticalError(err)

	var parsedBody []WebhookCrowdsec
	json.Unmarshal(jsonBody, &parsedBody)

	var emailCreds mail.SMTP
	emailCreds = mail.SMTP{
		Helo: os.Getenv("SMTP_HELO"),
		Host: os.Getenv("SMTP_HOST"),
		User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"),
		Port: 465}

	var resource resolveAbuseC.RIRObject
	var abuseContacts []string
	email := mail.Email{EnvelopeFrom: os.Getenv("SMTP_SENDER")}
	email.Headers = make(map[string]string)
	email.Headers["From"] = email.EnvelopeFrom

	buf := &bytes.Buffer{}
	var tmplvar tmplvar_portscan
	var __event __portscan_event

	for _, item := range parsedBody {
		// resolve abuse contacts
		resource.Resource = item.Source.ASN
		abuseContacts = resource.ResolveAbuseContactByRIPEstat()
		resource.Resource = item.Source.Ip
		abuseContacts = append(abuseContacts, resource.ResolveAbuseContactByRIPEstat()...)

		if len(abuseContacts) == 0 { /* generic fallback, available for IPv4 only */
			abuseContacts = append(abuseContacts, resource.ResolveAbuseContactByAbusix()...)
		}

		// remove duplicates
		abuseContacts = utils.GetUnique(abuseContacts)

		// template paremeters
		tmplvar = tmplvar_portscan{Ip: item.Source.Ip, Events: nil}

		for _, event := range item.Events {
			__event.Timestamp = event.Timestamp
			for _, meta := range event.Meta {
				if meta.Key == "source_port" {
					srcPort, _ := strconv.ParseUint(meta.Value, 10, 16)
					__event.SrcPort = uint16(srcPort)
				} else if meta.Key == "source_ip" {
					__event.SrcIp = meta.Value
				} else if meta.Key == "destination_port" {
					srcPort, _ := strconv.ParseUint(meta.Value, 10, 16)
					__event.DstPort = uint16(srcPort)
				} else if meta.Key == "destination_ip" {
					__event.DstIp = meta.Value
				}
			}
			tmplvar.Events = append(tmplvar.Events, __event)
		}

		// generate email
		email.EnvelopeTo = abuseContacts
		email.Headers["To"] = strings.Join(abuseContacts, ", ")

		// BCC
		email.EnvelopeTo = append(email.EnvelopeTo, email.EnvelopeFrom)

		buf.Reset()
		err = tmpl_portscan_subject.Execute(buf, tmplvar)
		utils.HandleCriticalError(err)
		email.Headers["Subject"] = buf.String()

		// TODO: fix timestamp length for proper tabulation
		buf.Reset()
		err = tmpl_portscan_body.Execute(buf, tmplvar)
		utils.HandleCriticalError(err)
		email.Body = buf.String()

		email.Send(emailCreds)

		log.Printf("Sent abuse complaint for IP %s was to %s\n", item.Source.Ip, email.Headers["To"])
	}
}

func main() {
	var err error

	// prepare templates
	tmpl_portscan_subject, err = template.ParseFiles("assets/templates/portscan/subject.tmpl")
	utils.HandleCriticalError(err)
	tmpl_portscan_body, err = template.ParseFiles("assets/templates/portscan/body.tmpl")
	utils.HandleCriticalError(err)

	log.Println("listening 127.0.0.1:8888")

	// start HTTP server
	http.HandleFunc("/webhook/crowdsec", webhookCrowdsec)
	http.ListenAndServe("127.0.0.1:8888", nil)
}
