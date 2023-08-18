package main

import (
	l "abuser/internal/logger"
	"abuser/internal/queryGeneric"
	"abuser/internal/reporter"
	"abuser/internal/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/netip"
	"strconv"
	"text/template"
)

var tmpl_portscan_subject, tmpl_portscan_body *template.Template

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
	Ip string `json:"ip"`
}

type WebhookCrowdsec struct {
	Events []crowdsecEvent `json:"events"`
	Source crowdsecSource  `json:"source"`
}

// TODO: reply early, process parsedBody in a separate goroutine
func webhookCrowdsec(w http.ResponseWriter, r *http.Request) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	utils.HandleCriticalError(err)

	var parsedBody []WebhookCrowdsec
	err = json.Unmarshal(jsonBody, &parsedBody)
	utils.HandleCriticalError(err)

	var abuseContacts []string

	var tmplvar tmplvar_portscan
	var __event __portscan_event

	go func() {
		for _, item := range parsedBody {
			ipAddr := netip.MustParseAddr(item.Source.Ip)

			abuseContacts = queryGeneric.IpToAbuseC(ipAddr)

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

			reporter.Report(abuseContacts, ipAddr, tmplvar, "portscan")
		}
	}()
}

func main() {
	var err error

	// prepare templates
	tmpl_portscan_subject, err = template.ParseFiles("assets/templates/portscan/subject.tmpl")
	utils.HandleCriticalError(err)
	tmpl_portscan_body, err = template.ParseFiles("assets/templates/portscan/body.tmpl")
	utils.HandleCriticalError(err)

	l.Logger.Println("listening 127.0.0.1:8888")

	// start HTTP server
	http.HandleFunc("/webhook/crowdsec", webhookCrowdsec)
	http.ListenAndServe("127.0.0.1:8888", nil)
}
