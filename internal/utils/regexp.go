package utils

import (
	"regexp"
)

func RegexpFindStringSubmatchMap(regexpVar *regexp.Regexp, matchVar string) map[string]string {
	regexpMatch := regexpVar.FindStringSubmatch(matchVar)
	mapResult := make(map[string]string)

	if len(regexpMatch) == 0 {
		return mapResult
	}

	subexpVar := regexpVar.SubexpNames()

	for i, name := range subexpVar {
		if i != 0 && name != "" {
			mapResult[name] = regexpMatch[i]
		}
	}

	return mapResult
}
