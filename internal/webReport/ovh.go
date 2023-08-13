package webReport

import (
	l "abuser/internal/logger"
	"abuser/internal/utils"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"time"
)

var categories map[string]string = map[string]string{
	"portscan": "intrusion",
}

func ToOVH(category string, ip netip.Addr, message string, email string) {
	var reqStruct struct {
		Category string `json:"category"`
		IP       string `json:"ip"`
		Logs     string `json:"logs"`
		Email    string `json:"email"`
		Fullname string `json:"fullname"`
	}
	reqStruct.Category = categories[category] // resolve our category into OVHs'
	reqStruct.IP = ip.String()
	reqStruct.Logs = message
	reqStruct.Email = email
	reqStruct.Fullname = "Automatic report"

	reqJson, err := json.Marshal(reqStruct)
	reqJsonBuf := bytes.NewBuffer(reqJson)

	httpC := http.Client{Timeout: time.Duration(10) * time.Second}
	res, err := httpC.Post(
		"https://abuse.eu.ovhapis.com/1.0/abuse/form/report?lang=en_US",
		"application/json;charset=utf-8", reqJsonBuf)
	utils.HandleCriticalError(err)

	resRaw, err := io.ReadAll(res.Body)
	utils.HandleCriticalError(err)

	err = res.Body.Close()
	utils.HandleCriticalError(err)

	if res.StatusCode == 200 {
		var resJson struct {
			Message string `json:"message"`
		}

		json.Unmarshal(resRaw, &resJson)

		if resJson.Message != "Report successfully created" {
			l.Logger.Printf("[%s] OVH rejected abuse complaint: %s\n", ip.String(), resJson.Message)
		} else {
			l.Logger.Printf("[%s] OVH accepted abuse complaint\n", ip.String())
		}
	} else {
		l.Logger.Printf("[%s] OVH rejected abuse complaint: %s\n", ip.String(), resRaw)
	}
}
