package resolveAbuseC

import (
	"abuser/internal/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
)

type apiResponse_data_asns struct {
	ASN int `json:"asn"`
}

type apiResponse_data struct {
	Abuse_contacts []string                `json:"abuse_contacts"`
	ASNs           []apiResponse_data_asns `json:"asns"`
}

type apiResponse struct {
	Data     apiResponse_data `json:"data"`
	Query_id string           `json:"query_id"`
	Status   string           `json:"status"`
}

func ResolveASNsFromIP(ip netip.Addr) []string {
	param := make(map[string]string)
	param["data_overload_limit"] = "ignore"
	param["min_peers_seeing"] = "30"
	param["resource"] = ip.String()

	response, err := craftRequest("prefix-overview", param)
	utils.HandleCriticalError(err)

	response_json, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	var asns []string = nil

	if response.StatusCode != 200 {
		return asns
	}

	var response_api apiResponse
	json.Unmarshal(response_json, &response_api)

	for _, asnObject := range response_api.Data.ASNs {
		asns = append(asns, strconv.Itoa(asnObject.ASN))
	}
	return asns
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
