package mail

import (
	"abuser/internal/utils"
	"crypto/tls"
	"fmt"
	"math"
	"net/smtp"
	"strings"
	"time"

	l "abuser/internal/logger"
)

type SMTP struct {
	Helo string
	Host string
	Port uint16
	User string
	Pass string
}

func (s *SMTP) GetAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

type Email struct {
	EnvelopeFrom string
	EnvelopeTo   []string
	Headers      map[string]string
	Body         string
}

const retryAttempts = 10

var errsTemporary = []string{
	"try later",
	"try again later",
	"temporarily deferred",
	"temporarily unavailable",
	"Greylist",
	"Silverlist",
	"Domain not found", // may be due to temporary DNS issue
	"Service currently unavailable",
	"Address verification in progress",
}

func (email *Email) Send(creds SMTP, attempt uint) {
	tlsConnonfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		ServerName:         creds.Host,
	}

	// establish TLS connection (encapsulate plaintext SMTP communitcation within it)
	tlsConn, err := tls.Dial("tcp", creds.GetAddr(), tlsConnonfig)

	/* TODO: better mechanism to requeue letters */
	if err != nil && attempt < retryAttempts {
		go func(email *Email, creds *SMTP, attempt uint) {
			durationStr := fmt.Sprintf("%fs", math.Pow(4, float64(attempt)))
			durationTime, err := time.ParseDuration(durationStr)
			if err != nil {
				utils.HandleCriticalError(err)
			} else {
				time.Sleep(durationTime)
				email.Send(*creds, attempt)
			}
		}(email, &creds, attempt+1)
	} else {
		utils.HandleCriticalError(err)
	}

	// establish SMTP connection
	smtpConn, err := smtp.NewClient(tlsConn, creds.Host)
	utils.HandleCriticalError(err)

	// establish SMTP communication by introducing yourself
	err = smtpConn.Hello(creds.Helo)
	utils.HandleCriticalError(err)

	// login into SMTP account
	auth := smtp.PlainAuth("", creds.User, creds.Pass, creds.Host)
	err = smtpConn.Auth(auth)
	utils.HandleCriticalError(err)

	// acknowledge who is the sender for SMTP server
	err = smtpConn.Mail(email.EnvelopeFrom)
	utils.HandleCriticalError(err)

	// acknowledge who are the recipients for SMTP server
	recipientCount := len(email.EnvelopeTo)
	var acceptedRecipients []string
	for _, recipient := range email.EnvelopeTo {
		err = smtpConn.Rcpt(recipient)

		if err == nil {
			acceptedRecipients = append(acceptedRecipients, recipient)
		} else if attempt < retryAttempts {
			errStr := err.Error()

			// TODO: consider matching on SMTP error codes instead?
			isTemporary := false
			for _, temporaryErrStr := range errsTemporary {
				isTemporary = isTemporary || strings.Contains(errStr, temporaryErrStr)
				if isTemporary {
					break
				}
			}

			if isTemporary {
				l.Logger.Printf("[%s] Retrying %s for %d time...\n", email.Headers["Subject"], recipient, attempt+1)
				go func(email *Email, creds *SMTP, attempt uint, recipient string) {
					durationStr := fmt.Sprintf("%fs", math.Pow(4, float64(attempt)))
					durationTime, err := time.ParseDuration(durationStr)
					if err != nil {
						utils.HandleCriticalError(err)
					} else {
						time.Sleep(durationTime)

						newEmail := *email
						newEmail.EnvelopeTo = []string{recipient}
						go newEmail.Send(*creds, attempt)
					}
				}(email, &creds, attempt+1, recipient)
			} else {
				l.Logger.Printf("[%s] Invalid recipient <%s>: %s\n", email.Headers["Subject"], recipient, err.Error())
			}
		}

		if err != nil {
			recipientCount--
		}
	}

	if recipientCount >= 1 {
		// ask the SMTP server to receive our letter
		w, err := smtpConn.Data()
		utils.HandleCriticalError(err)

		// create the letter in an appropriate format by combining headers and body into single string
		rawEmail := ""
		for k, v := range email.Headers {
			rawEmail += fmt.Sprintf("%s: %s\r\n", strings.TrimSpace(k), strings.TrimSpace(v))
		}
		rawEmail += "\r\n" + strings.TrimSpace(email.Body)

		// send the letter to the SMTP server
		_, err = w.Write([]byte(rawEmail))
		utils.HandleCriticalError(err)

		// appropriately acknowledge the end of the letter
		err = w.Close()
		utils.HandleCriticalError(err)

		l.Logger.Printf("[%s] Abuse complaint was sent to %s\n", email.Headers["Subject"], strings.Join(acceptedRecipients, ", "))
	} else {
		// reset mail transaction because we have no recipients
		err := smtpConn.Reset()
		utils.HandleCriticalError(err)
		l.Logger.Printf("[%s] The letter has no valid recipients\n", email.Headers["Subject"])
	}

	// appropriately end our communication with the server
	err = smtpConn.Quit()
	utils.HandleCriticalError(err)

	tlsConn.Close()
}
