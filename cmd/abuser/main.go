package main

import (
	"abuser/internal/querygeneric"
	"abuser/internal/reporter"
	"abuser/internal/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	l "abuser/internal/logger"
)

type _PortscanEvent struct {
	SrcIP     string // compatibility with Body template
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Timestamp string
}

type tmplvarPortscan struct {
	IP     string // compatibility with Subject template
	Events []_PortscanEvent
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
	IP string `json:"ip"`
}

type WebhookCrowdsec struct {
	Events []crowdsecEvent `json:"events"`
	Source crowdsecSource  `json:"source"`
}

func webhookCrowdsec(_ http.ResponseWriter, r *http.Request) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	utils.HandleCriticalError(err)

	var parsedBody []WebhookCrowdsec
	err = json.Unmarshal(jsonBody, &parsedBody)
	utils.HandleCriticalError(err)

	var abuseContacts []string
	var bogonStatus querygeneric.BogonStatus

	var tmplvar tmplvarPortscan
	var _Event _PortscanEvent

	go func() {
		for _, item := range parsedBody {
			ipAddr := utils.NormalizeIpAddr(item.Source.IP)

			abuseContacts, bogonStatus = querygeneric.IPAddrToAbuseC(ipAddr)
			if bogonStatus.IsBogonIP || len(bogonStatus.BogonsAS) > 0 {
				// TODO: handle bogons and report them accordingly
				l.Logger.Printf("[%s] Bogon resource! Bogon reports are currently not implemented, skipping.\n", item.Source.IP)
				return
			}

			// template paremeters
			tmplvar = tmplvarPortscan{IP: item.Source.IP, Events: nil}

			for _, event := range item.Events {
				_Event.Timestamp = event.Timestamp
				for _, meta := range event.Meta {
					switch meta.Key {
					case "source_port":
						srcPort, _ := strconv.ParseUint(meta.Value, 10, 16)
						_Event.SrcPort = uint16(srcPort)
						break
					case "source_ip":
						_Event.SrcIP = meta.Value
						break
					case "destination_port":
						dstPort, _ := strconv.ParseUint(meta.Value, 10, 16)
						_Event.DstPort = uint16(dstPort)
						break
					case "destination_ip":
						_Event.DstIP = meta.Value
						break
					}
				}
				tmplvar.Events = append(tmplvar.Events, _Event)
			}

			reporter.Report(abuseContacts, ipAddr, tmplvar, "portscan")
		}
	}()
}

func main() {
	l.Logger.Println("listening 127.0.0.1:8888")

	http.HandleFunc("/webhook/crowdsec", webhookCrowdsec)
	err := http.ListenAndServe("127.0.0.1:8888", nil) // #nosec G114
	panic(err)
}
