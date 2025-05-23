package main

import (
	"abuser/internal/querygeneric"
	"abuser/internal/reporter"
	"abuser/internal/structs"
	"abuser/internal/utils"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	l "abuser/internal/logger"
)

type crowdsecEvent struct {
	Meta      []crowdsecEventMeta `json:"meta"`
	Timestamp string              `json:"timestamp"`
}

type crowdsecEventMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type crowdsecSource struct {
	IP string `json:"ip"`
}

type WebhookCrowdsec struct {
	Events []crowdsecEvent `json:"events"`
	Source crowdsecSource  `json:"source"`
}

func webhookCrowdsec(_ http.ResponseWriter, r *http.Request) {
	jsonBody, err := io.ReadAll(r.Body)
	utils.HandleCriticalError(err)

	err = r.Body.Close()
	utils.HandleCriticalError(err)

	var parsedBody []WebhookCrowdsec
	err = json.Unmarshal(jsonBody, &parsedBody)
	utils.HandleCriticalError(err)

	var abuseContacts []string

	var tmplData structs.TemplateData[structs.PortscanEvent]
	var tmpEvent structs.PortscanEvent

	go func() {
		for _, item := range parsedBody {
			ipAddr := utils.NormalizeIpAddr(item.Source.IP)

			abuseContacts = querygeneric.IPAddrToAbuseC(ipAddr)

			tmplData = structs.TemplateData[structs.PortscanEvent]{IP: item.Source.IP, Events: nil}

			for _, event := range item.Events {
				for _, meta := range event.Meta {
					switch meta.Key {
					case "timestamp":
						tmpEvent.Timestamp = event.Timestamp
					case "source_port":
						srcPort, _ := strconv.ParseUint(meta.Value, 10, 16)
						tmpEvent.SrcPort = uint16(srcPort)
					case "source_ip":
						tmpEvent.SrcIP = meta.Value
					case "destination_port":
						dstPort, _ := strconv.ParseUint(meta.Value, 10, 16)
						tmpEvent.DstPort = uint16(dstPort)
					case "destination_ip":
						tmpEvent.DstIP = meta.Value
						tmpEvent.DstIP = strings.ReplaceAll(tmpEvent.DstIP, ".", "x")
						tmpEvent.DstIP = strings.ReplaceAll(tmpEvent.DstIP, ":", "x")
					}
				}
				tmplData.Events = append(tmplData.Events, tmpEvent)
			}

			reporter.Report(abuseContacts, ipAddr, tmplData, "portscan")
		}
	}()
}

func main() {
	l.Logger.Println("listening 127.0.0.1:8888")

	http.HandleFunc("/webhook/crowdsec", webhookCrowdsec)
	err := http.ListenAndServe("127.0.0.1:8888", nil) // #nosec G114
	panic(err)
}
