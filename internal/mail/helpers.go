package mail

import (
	"abuser/internal/utils"
	"regexp"
	"strings"
)

var (
	smtpErr       = "(?P<replyCode>\\d{3})(?: |\\-)(?P<rawStatusCode>[\\d\\.]{5}|)(?: |)(?:\\<\\S+\\>\\: |)(?P<reason>.+)"
	regexpSmtpErr = regexp.MustCompile(smtpErr)

	postfixUnverifiedAddressErr   = "Recipient address rejected: unverified address: "
	postfixOngoingVerificationErr = "Address verification in progress"

	tcpErr       = "connect to [\\S]+\\[(?:[\\d\\.]+|[\\da-f\\:]+)\\]\\:\\d+\\: (?P<reason>.+)"
	regexpTcpErr = regexp.MustCompile(tcpErr)

	nestedSmtpErr       = "host [\\S]+\\[(?:[\\d\\.]+|[\\da-f\\:]+)\\] said\\: (?P<reason>.+)"
	regexpNestedSmtpErr = regexp.MustCompile(nestedSmtpErr)
)

// Analyzes SMTP reply, returns whether error is temporary or a fatal issue.
//
// Returns whether the error is fatal (bool) and relevant error part (string).
func IsFatalSmtpError(smtpErr string) (bool, string) {
	var (
		isFatal    = true
		smtpResult = utils.RegexpFindStringSubmatchMap(regexpSmtpErr, smtpErr)
	)

	// RFC821, reply code (450, 550 etc.)
	replyCode, _ := smtpResult["replyCode"]

	// RFC3463, status code (2.1.23, 4.1.1 etc.)
	rawStatusCode, _ := smtpResult["rawStatusCode"]

	// human readable part, sometimes is nested SMTP error (i.e. postfix
	// address verification)
	reason, _ := smtpResult["reason"]

	// nothing more to analyze
	if len(rawStatusCode) == 0 {
		switch strings.Split(replyCode, "")[0] {
		case "4":
			isFatal = false
		case "5":
			isFatal = true
		}

		return isFatal, smtpErr
	}

	statusCode := strings.Split(rawStatusCode, ".")

	if statusCode[0] == "5" {
		return true, smtpErr
	} else if statusCode[0] == "4" {
		if strings.Index(reason, postfixUnverifiedAddressErr) == 0 {
			offset := len(postfixUnverifiedAddressErr)
			smtpErr = reason[offset:]

			if smtpErr == postfixOngoingVerificationErr {
				return false, smtpErr
			} else {
				if regexpTcpErr.MatchString(smtpErr) {
					smtpResult = utils.RegexpFindStringSubmatchMap(regexpTcpErr, smtpErr)
					smtpErr, _ = smtpResult["reason"]

					return false, smtpErr
				}

				if regexpNestedSmtpErr.MatchString(smtpErr) {
					smtpResult = utils.RegexpFindStringSubmatchMap(regexpNestedSmtpErr, smtpErr)
					return IsFatalSmtpError(smtpResult["reason"])
				}
			}
		} else {
			return false, smtpErr
		} // TODO? other Postfix configurations and email servers
	}

	return isFatal, smtpErr
}
