package resolveAbuseC

import (
	"abuser/internal/utils"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

type RIRObject struct {
	Resource string // This could be anything: ASN, IP address
}

type apiResponse_data struct {
	Abuse_contacts []string `json:"abuse_contacts"`
}

type apiResponse struct {
	Data     apiResponse_data `json:"data"`
	Query_id string           `json:"query_id"`
	Status   string           `json:"status"`
}

func (o *RIRObject) ResolveAbuseContact() []string {
	param := make(map[string]string)
	param["resource"] = o.Resource

	response, err := craftRequest("abuse-contact-finder", param)
	utils.HandleCriticalError(err)

	response_json, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	if response.StatusCode != 200 {
		log.Fatalln("RIPEstat Data API error! HTTP status code: " + strconv.Itoa(response.StatusCode))
	}

	var response_api apiResponse

	json.Unmarshal(response_json, &response_api)

	return response_api.Data.Abuse_contacts
}

func craftRequest(dataCall string, param map[string]string) (*http.Response, error) {
	apiUrl, _ := url.Parse("https://stat.ripe.net/data/" + dataCall + "/data.json")
	param["sourceapp"] = "SkhronAbuseComplaintSender"

	query := apiUrl.Query()
	for k, v := range param {
		query.Add(k, v)
	}
	apiUrl.RawQuery = query.Encode()

	response, err := http.Get(apiUrl.String())
	if err != nil {
		return nil, err
	}

	return response, nil
}
