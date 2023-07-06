package mail

import (
	"abuser/internal/utils"
	"crypto/tls"
	"fmt"
	"net/smtp"
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

func (email *Email) Send(creds SMTP) {
	// smtp_helo := os.Getenv("SMTP_HELO")
	// if len(smtp_helo) == 0 {
	// 	smtp_helo = "dummy.encryp.ch"
	// }

	// smtp_host := os.Getenv("SMTP_HOSTNAME")
	// smtp_user := os.Getenv("SMTP_USERNAME")
	// smtp_pass := os.Getenv("SMTP_PASSWORD")

	tlsConnonfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         creds.Host,
	}

	// establish TLS connection (encapsulate plaintext SMTP communitcation within it)
	tlsConn, err := tls.Dial("tcp", creds.GetAddr(), tlsConnonfig)
	utils.HandleCriticalError(err)

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
	for _, recipient := range email.EnvelopeTo {
		err = smtpConn.Rcpt(recipient)
		utils.HandleCriticalError(err)
	}

	// ask the SMTP server to receive our letter
	w, err := smtpConn.Data()
	utils.HandleCriticalError(err)

	// create the letter in an appropriate format by combining headers and body into single string
	rawEmail := ""
	for k, v := range email.Headers {
		rawEmail += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	rawEmail += "\r\n" + email.Body

	// send the letter to the SMTP server
	_, err = w.Write([]byte(rawEmail))
	utils.HandleCriticalError(err)

	// appropriately acknowledge the end of the letter
	err = w.Close()
	utils.HandleCriticalError(err)

	// appropriately end our communication with the server
	smtpConn.Quit()
	tlsConn.Close()
}
