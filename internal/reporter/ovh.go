package reporter

import (
	"abuser/internal/utils"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	l "abuser/internal/logger"
)

var ovhCategories = map[string]string{
	"portscan": "intrusion",
}

func ovhSolveChallenge(rawURL *url.URL) string {
	id := rawURL.Query().Get("id")
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func ToOVH(category string, ip netip.Addr, message string, email string) {
	var reqStruct struct {
		Category     string `json:"category"`
		Confirmation bool   `json:"confirmation"`
		Plaintiff    struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"plaintiff"`
		Data struct {
			IP   string `json:"ip"`
			Logs string `json:"logs"`
		} `json:"data"`
	}
	reqStruct.Category = ovhCategories[category] // resolve our category into OVHs'
	reqStruct.Confirmation = true
	reqStruct.Data.IP = ip.String()
	reqStruct.Data.Logs = message
	reqStruct.Plaintiff.Email = email
	reqStruct.Plaintiff.Name = "Skhron OU"

	reqJSON, err := json.Marshal(reqStruct)
	utils.HandleCriticalError(err)
	reqJSONBuf := bytes.NewBuffer(reqJSON)

	var challengeURL *url.URL = nil
	var rawURL, solution = "", ""
	var netClient = &http.Client{Timeout: time.Second * 60}
	req, err := http.NewRequest("POST", "https://abuse.eu.ovhapis.com/1.0/form/", reqJSONBuf)
	utils.HandleCriticalError(err)

	req.Header.Add("Accept", "*/*")
	req.Header.Add("Content-Type", "application/json")
ovhRetry:
	if challengeURL != nil && solution != "" {
		req.Header.Add("X-Challenge-Payload", rawURL)
		req.Header.Add("X-Challenge-Response", solution)
	}

	res, err := netClient.Do(req)
	utils.HandleCriticalError(err)

	resRaw, err := io.ReadAll(res.Body)
	utils.HandleCriticalError(err)

	err = res.Body.Close()
	utils.HandleCriticalError(err)

	switch res.StatusCode {
	case 400:
		var resJSON struct {
			Class string `json:"class"`
			Body  struct {
				Payload string `json:"payload"`
				Type    string `json:"type"`
			} `json:"body"`
		}

		err = json.Unmarshal(resRaw, &resJSON)
		if err != nil {
			goto ovhError
		}

		if resJSON.Class == "Client::BadRequest::ChallengeRequired" {
			if resJSON.Body.Type == "url" && rawURL == "" && solution == "" {
				challengeURL, err = url.Parse(resJSON.Body.Payload)
				if err != nil {
					goto ovhError
				} else {
					rawURL = resJSON.Body.Payload
				}

				solution = ovhSolveChallenge(challengeURL)
				goto ovhRetry
			}
		}
	case 200:
		var resJSON struct {
			Message string `json:"message"`
		}

		err = json.Unmarshal(resRaw, &resJSON)
		if err != nil {
			goto ovhError
		}

		if resJSON.Message != "Report successfully created" {
			goto ovhError
		} else {
			l.Logger.Printf("[%s] OVH accepted abuse complaint\n", ip.String())
		}

		return
	}

ovhError:
	l.Logger.Printf("[%s] OVH rejected abuse complaint. Request: \"%s\". Response: \"%s\"\n", ip.String(), reqJSON, resRaw)
}
