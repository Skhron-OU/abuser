package mail

import "fmt"

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
