package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
)

func main() {
	smtp_helo := os.Getenv("SMTP_HELO")
	if len(smtp_helo) == 0 {
		smtp_helo = "dummy.encryp.ch"
	}

	smtp_host := os.Getenv("SMTP_HOSTNAME")
	smtp_port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if smtp_port < 1 || smtp_port > 65535 {
		smtp_port = 465
	}

	smtp_srv := fmt.Sprintf("%s:%d", smtp_host, uint16(smtp_port))
	smtp_user := os.Getenv("SMTP_USERNAME")
	smtp_pass := os.Getenv("SMTP_PASSWORD")

	auth := smtp.PlainAuth("", smtp_user, smtp_pass, smtp_host)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtp_host,
	}

	tlsc, err := tls.Dial("tcp", smtp_srv, tlsconfig)
	if err != nil {
		log.Panic(err)
	}

	smtpc, err := smtp.NewClient(tlsc, smtp_host)
	if err != nil {
		log.Panic(err)
	}

	if err = smtpc.Hello(smtp_helo); err != nil {
		log.Panic(err)
	}

	if err = smtpc.Auth(auth); err != nil {
		log.Panic(err)
	}

	from := mail.Address{"", smtp_user}
	to := mail.Address{"", "example@at.encryp.ch"}
	subj := "This is the email subject"
	body := "This is an example body.\n With two lines."

	// Setup headers
	headers := make(map[string]string)
	headers["From"] = from.String()
	headers["To"] = to.String()
	headers["Subject"] = subj

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// To && From
	if err = smtpc.Mail(from.Address); err != nil {
		log.Panic(err)
	}

	if err = smtpc.Rcpt(to.Address); err != nil {
		log.Panic(err)
	}

	// Data
	w, err := smtpc.Data()
	if err != nil {
		log.Panic(err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		log.Panic(err)
	}

	err = w.Close()
	if err != nil {
		log.Panic(err)
	}

	smtpc.Quit()
	tlsc.Close()
}
