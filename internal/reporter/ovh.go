package reporter

import (
	"abuser/internal/utils"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"time"

	l "abuser/internal/logger"
)

var ovhCategories = map[string]string{
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
	reqStruct.Category = ovhCategories[category] // resolve our category into OVHs'
	reqStruct.IP = ip.String()
	reqStruct.Logs = message
	reqStruct.Email = email
	reqStruct.Fullname = "Automatic report"

	reqJSON, err := json.Marshal(reqStruct)
	utils.HandleCriticalError(err)
	reqJSONBuf := bytes.NewBuffer(reqJSON)

	var netClient = &http.Client{Timeout: time.Second * 60}
	res, err := netClient.Post(
		"https://abuse.eu.ovhapis.com/1.0/abuse/form/report?lang=en_US",
		"application/json;charset=utf-8", reqJSONBuf)
	utils.HandleCriticalError(err)

	resRaw, err := io.ReadAll(res.Body)
	utils.HandleCriticalError(err)

	err = res.Body.Close()
	utils.HandleCriticalError(err)

	if res.StatusCode == 200 {
		var resJSON struct {
			Message string `json:"message"`
		}

		err = json.Unmarshal(resRaw, &resJSON)
		utils.HandleCriticalError(err)

		if resJSON.Message != "Report successfully created" {
			l.Logger.Printf("[%s] OVH rejected abuse complaint: %s\n", ip.String(), resJSON.Message)
		} else {
			l.Logger.Printf("[%s] OVH accepted abuse complaint\n", ip.String())
		}
	} else {
		l.Logger.Printf("[%s] OVH rejected abuse complaint: %s\n", ip.String(), resRaw)
	}
}
