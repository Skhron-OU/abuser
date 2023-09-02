package queryRipeStat

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

type apiResponse_data_record struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type apiResponse_data struct {
	Abuse_contacts []string                    `json:"abuse_contacts"`
	ASNs           []apiResponse_data_asns     `json:"asns"`
	IRR_Records    [][]apiResponse_data_record `json:"irr_records"`
}

type apiResponse struct {
	Data     apiResponse_data `json:"data"`
	Query_id string           `json:"query_id"`
	Status   string           `json:"status"`
}

func IpToAsn(ip netip.Addr) []string {
	var irrAsns map[string]bool = ipToAsn_irr(ip)
	var bgpAsns map[string]bool = ipToAsn_bgp(ip)

	var asns []string
	for asn := range bgpAsns {
		if _, ok := irrAsns[asn]; ok {
			asns = append(asns, asn)
		}
	}
	return asns
}

func ipToAsn_bgp(ip netip.Addr) map[string]bool {
	param := make(map[string]string)
	param["resource"] = ip.String()

	response, err := craftRequest("prefix-overview", param)
	utils.HandleCriticalError(err)

	response_json, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	var asns map[string]bool = make(map[string]bool)

	if response.StatusCode != 200 {
		return map[string]bool{}
	}

	var response_api apiResponse
	json.Unmarshal(response_json, &response_api)

	for _, asnObject := range response_api.Data.ASNs {
		asns[strconv.Itoa(asnObject.ASN)] = true
	}
	return asns
}

func ipToAsn_irr(ip netip.Addr) map[string]bool {
	param := make(map[string]string)
	param["resource"] = ip.String()

	response, err := craftRequest("whois", param)
	utils.HandleCriticalError(err)

	response_json, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	var asns map[string]bool = make(map[string]bool)

	if response.StatusCode != 200 {
		return map[string]bool{}
	}

	var response_api apiResponse
	json.Unmarshal(response_json, &response_api)

	for _, records := range response_api.Data.IRR_Records {
		for _, record := range records {
			if record.Key == "origin" {
				asns[record.Value] = true
			}
		}
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
