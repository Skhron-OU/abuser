package queryripestat

import (
	"abuser/internal/utils"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	l "abuser/internal/logger"
)

type apiResponseDataAsns struct {
	ASN int `json:"asn"`
}

type apiResponseDataRecord struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type apiResponseDataBgpstate struct {
	Path []uint `json:"path"`
}

type apiResponseDataRoute struct {
	InBGP  bool   `json:"in_bgp"`
	InIRR  bool   `json:"in_whois"`
	Origin uint   `json:"origin"`
	Prefix string `json:"prefix"`
}

type apiResponseData struct {
	AbuseContacts []string                  `json:"abuse_contacts"`
	ASNs          []apiResponseDataAsns     `json:"asns"`
	IRRRecords    [][]apiResponseDataRecord `json:"irr_records"`
	BGPState      []apiResponseDataBgpstate `json:"bgp_state"`
	NRRoutes      uint                      `json:"nr_routes"`
	Routes        []apiResponseDataRoute    `json:"routes"`
}

type apiResponseRoa []struct {
	Status   string `json:"status"`
	Resource string `json:"resource"`
}

type apiResponse[T any] struct {
	Data           T      `json:"data"`
	DataCallStatus string `json:"data_call_status"`
	QueryID        string `json:"query_id"`
	Status         string `json:"status"`
	Message        string `json:"message"`
}

type BgpState struct {
	Origin   []uint
	Upstream []uint
}

type RoutingConsistency struct {
	InBGP bool
	InIRR bool
}

func IPAddrToAS(ip netip.Addr) []uint {
	asnsBgp, mostSpecificPrefix := routingConsistency(ip)
	if mostSpecificPrefix == nil {
		return utils.Keys(asnsBgp)
	}

	asnsRoa := prefixRoa(*mostSpecificPrefix, utils.Keys(asnsBgp))

	asnsToFilter := utils.GetUnique(append(utils.Keys(asnsBgp), utils.Keys(asnsRoa)...))

	if len(asnsToFilter) == 1 {
		return asnsToFilter
	} else {
		var asns []uint

		for _, asn := range asnsToFilter {
			legacyInfo, isLegacy := asnsBgp[asn]
			_, isRpkiValid := asnsRoa[asn]

			if !isLegacy {
				continue
			}

			if legacyInfo.InBGP && (legacyInfo.InIRR || isRpkiValid) {
				asns = append(asns, asn)
			}
		}

		return asns
	}
}

func prefixRoa(net netip.Prefix, asnsRaw []uint) map[uint]bool {
	param := make(map[string]string)
	param["prefix"] = net.String()

	var asnsStr = make([]string, len(asnsRaw))
	for i, asn := range asnsRaw {
		asnsStr[i] = strconv.Itoa(int(asn))
	}
	asnsStr = append(asnsStr, "0", "65536") // ensure that we always receive at least two entries
	param["resources"] = strings.Join(asnsStr, ",")

	responseJSON, err := craftRequest("rpki-validation", param)
	asnsValid := make(map[uint]bool, 0)
	if err != nil {
		return asnsValid
	}

	var responseAPI apiResponse[apiResponseRoa]
	err = json.Unmarshal(responseJSON, &responseAPI)
	utils.HandleCriticalError(err)

	for _, roaObject := range responseAPI.Data {
		if roaObject.Status == "valid" {
			asn, _ := strconv.Atoi(roaObject.Resource)
			asnsValid[uint(asn)] = true
		}
	}
	return asnsValid
}

func routingConsistency(ip netip.Addr) (map[uint]RoutingConsistency, *netip.Prefix) {
	param := make(map[string]string)
	param["resource"] = ip.String()

	responseJSON, err := craftRequest("prefix-routing-consistency", param)
	if err != nil {
		l.Logger.Printf("[prefix-routing-constitency:%s] %s", ip.String(), err.Error())
		return map[uint]RoutingConsistency{}, nil
	}

	var responseAPI apiResponse[apiResponseData]
	if err = json.Unmarshal(responseJSON, &responseAPI); err != nil {
		l.Logger.Printf("[prefix-routing-constitency:%s] %s", ip.String(), err.Error())
		return map[uint]RoutingConsistency{}, nil
	}

	asns := make(map[uint]RoutingConsistency, 0)
	mostSpecificPrefix := netip.PrefixFrom(ip, 0)

	for _, routeObject := range responseAPI.Data.Routes {
		thisPrefix, _ := netip.ParsePrefix(routeObject.Prefix)
		if mostSpecificPrefix.Bits() < thisPrefix.Bits() {
			mostSpecificPrefix = thisPrefix
		}

		asns[routeObject.Origin] = RoutingConsistency{routeObject.InBGP, routeObject.InIRR}
	}

	return asns, &mostSpecificPrefix
}

func AnalyzeBgpState(ip netip.Addr) BgpState {
	param := make(map[string]string)
	param["resource"] = ip.String()

	responseJSON, err := craftRequest("bgp-state", param)

	if err != nil {
		return BgpState{}
	}

	var responseAPI apiResponse[apiResponseData]
	err = json.Unmarshal(responseJSON, &responseAPI)
	utils.HandleCriticalError(err)

	var origins = make(map[uint]bool, 0)
	var upstreams = make(map[uint]uint, 0)
	var upstream uint
	var asPath []uint
	var asPathLen uint

	for _, route := range responseAPI.Data.BGPState {
		// remove prepends if any
		for i, asn := range route.Path {
			if i == 0 {
				asPath = []uint{asn}
			} else if asPath[asPathLen-1] != asn {
				asPath = append(asPath, asn)
			}

			asPathLen = uint(len(asPath))
		}

		// use two last asns in AS_PATH as origin and upstream accordingly
		origins[asPath[asPathLen-1]] = true
		if asPathLen > 1 {
			upstream = asPath[asPathLen-2]
			upstreams[upstream]++
		}

		asPath = nil
	}

	// quirk to detect real upstreams and not peers
	totalUpstreams := len(upstreams)
	for upstream, freq := range upstreams {
		if float32(freq) < float32(responseAPI.Data.NRRoutes)/float32(totalUpstreams) {
			delete(upstreams, upstream)
		}
	}

	return BgpState{Origin: utils.Keys(origins), Upstream: utils.Keys(upstreams)}
}

func craftRequest(dataCall string, param map[string]string) ([]byte, error) {
	apiURL, _ := url.Parse("https://stat.ripe.net/data/" + dataCall + "/data.json")
	param["sourceapp"] = "SkhronAbuseComplaintSender"

	query := apiURL.Query()
	for k, v := range param {
		query.Add(k, v)
	}
	apiURL.RawQuery = query.Encode()

	var (
		netClient    = &http.Client{Timeout: time.Second * 60}
		responseJSON = new([]byte)
		responseAPI  apiResponse[json.RawMessage]
	)

	// retry on any encountered error
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second * time.Duration(i*5))

		response, err := netClient.Get(apiURL.String())
		if err != nil {
			continue
		}

		if response.StatusCode != 200 {
			l.Logger.Printf("[dataCall:%s, param:%+v] StatusCode: %d\n", dataCall, param, response.StatusCode)
			continue
		}

		*responseJSON, err = io.ReadAll(response.Body)
		response.Body.Close()
		utils.HandleCriticalError(err)

		err = json.Unmarshal(*responseJSON, &responseAPI)
		utils.HandleCriticalError(err)

		if responseAPI.Status == "ok" {
			break
		}
	}

	if responseAPI.Status != "ok" {
		l.Logger.Printf("[dataCall:%s, param:%+v] Status: %s, Message: %s\n", dataCall, param, responseAPI.Status, responseAPI.Message)
		return nil, errors.New(responseAPI.Status)
	}

	if !strings.HasPrefix(responseAPI.DataCallStatus, "supported") {
		l.Logger.Printf("[dataCall:%s, param:%+v] DataCallStatus: %s\n", dataCall, param, responseAPI.DataCallStatus)
	}

	return *responseJSON, nil
}
