package mail

import (
	"abuser/internal/utils"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/smtp"
	"strings"
	"time"

	l "abuser/internal/logger"
)

func NewEmailWorkerPool(numWorkers int, creds SMTP) *EmailWorkerPool {
	if numWorkers <= 0 {
		numWorkers = defaultWorkers
	}

	return &EmailWorkerPool{
		Creds:      creds,
		jobs:       make(chan EmailJob, numWorkers*10), // buffered channel
		numWorkers: numWorkers,
		conns:      make(chan *EmailConnection, numWorkers),
		quit:       make(chan struct{}),
	}
}

func (p *EmailWorkerPool) Start() {
	p.wg.Add(p.numWorkers)
	for i := 0; i < p.numWorkers; i++ {
		go p.worker(i)
	}
}

func (p *EmailWorkerPool) Stop() {
	close(p.quit)
	p.wg.Wait()
	close(p.jobs)
	close(p.conns)
}

func (p *EmailWorkerPool) Submit(email *Email, attempt uint) bool {
	job := EmailJob{
		Email:   email,
		Attempt: attempt,
	}

	select {
	case p.jobs <- job:
		return true
	case <-p.quit:
		l.Logger.Printf("[%s] Worker pool is shutting down, job rejected\n", email.Headers["Subject"])
		return false
	}
}

func (p *EmailWorkerPool) worker(id int) {
	defer p.wg.Done()

	l.Logger.Printf("Worker %d started\n", id)

	for {
		select {
		case job, ok := <-p.jobs:
			if !ok {
				l.Logger.Printf("Worker %d: job channel closed\n", id)
				return
			}
			p.processJob(job)
		case <-p.quit:
			l.Logger.Printf("Worker %d shutting down\n", id)
			return
		}
	}
}

func (p *EmailWorkerPool) processJob(job EmailJob) {
	var err error
	var emailConnection *EmailConnection
	var smtpConn *smtp.Client
	var acceptedRecipients []string

	email := job.Email
	auth := smtp.PlainAuth("", p.Creds.User, p.Creds.Pass, p.Creds.Host)
	attempt := job.Attempt
	recipientCount := len(email.EnvelopeTo)

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		ServerName:         p.Creds.Host,
	}

	// try to reuse existing connection, initiate new if no existing
	select {
	case emailConnection = <-p.conns:
		break
	default:
		emailConnection = new(EmailConnection)
		goto initConn
	}

	// check if it is alive, initiate new if dead
	if err = emailConnection.SmtpConn.Noop(); err != nil {
		if err != io.EOF {
			l.Logger.Printf("Error while reusing SMTP connection: %s\n", err.Error())
		}

		if err = emailConnection.SmtpConn.Close(); err != nil {
			l.Logger.Printf("Error while closing SMTP connection: %s\n", err.Error())
		}

		if err = emailConnection.TlsConn.Close(); err != nil {
			if err != net.ErrClosed {
				l.Logger.Printf("Error while closing TLS connection: %s\n", err.Error())
			}
		}

		goto initConn
	}

useConn:
	smtpConn = emailConnection.SmtpConn
	defer func() {
		p.conns <- emailConnection
	}()

	if err = smtpConn.Mail(email.EnvelopeFrom); err != nil {
		p.handleConnectionError(email, attempt, err)
		return
	}

	for _, recipient := range email.EnvelopeTo {
		err = smtpConn.Rcpt(recipient)

		if err == nil {
			acceptedRecipients = append(acceptedRecipients, recipient)
		} else {
			recipientCount--
			p.handleRecipientError(email, attempt, recipient, err)
		}
	}

	if recipientCount > 0 {
		w, err := smtpConn.Data()
		if err != nil {
			p.handleConnectionError(email, attempt, err)
			goto resetConn
		}

		rawEmail := p.buildRawEmail(email)
		if _, err = w.Write([]byte(rawEmail)); err != nil {
			p.handleConnectionError(email, attempt, err)
			goto resetConn
		}

		if err = w.Close(); err != nil {
			p.handleConnectionError(email, attempt, err)
			goto resetConn
		}

		l.Logger.Printf("[%s] Abuse complaint was sent to %s\n",
			email.Headers["Subject"], strings.Join(acceptedRecipients, ", "))
		return
	}

	// reset mail transaction because we have no recipients
resetConn:
	if err := smtpConn.Reset(); err != nil {
		l.Logger.Printf("Error while clearing SMTP connection: %s\n", err.Error())
	}

	return

initConn:
	if emailConnection.TlsConn, err = tls.Dial("tcp", p.Creds.GetAddr(), tlsConfig); err != nil {
		p.handleConnectionError(email, attempt, err)
		return
	}

	if emailConnection.SmtpConn, err = smtp.NewClient(emailConnection.TlsConn, p.Creds.Host); err != nil {
		p.handleConnectionError(email, attempt, err)
		return
	}

	// must be called only for new connections
	if err = emailConnection.SmtpConn.Hello(p.Creds.Helo); err != nil {
		p.handleConnectionError(email, attempt, err)
		return
	}

	if err = emailConnection.SmtpConn.Auth(auth); err != nil {
		p.handleConnectionError(email, attempt, err)
		return
	}

	goto useConn
}

func (p *EmailWorkerPool) handleConnectionError(email *Email, attempt uint, err error) {
	if attempt < retryAttempts {
		l.Logger.Printf("[%s] Connection error (attempt %d): %v. Scheduling retry...\n",
			email.Headers["Subject"], attempt, err)
		p.scheduleRetry(email, attempt+1)
	} else {
		utils.HandleCriticalError(err)
	}
}

func (p *EmailWorkerPool) handleRecipientError(email *Email, attempt uint, recipient string, err error) {
	if attempt < retryAttempts {
		isFatal, errStr := IsFatalSmtpError(err.Error())

		if !isFatal {
			l.Logger.Printf("[%s] Retrying %s for %d time...\n",
				email.Headers["Subject"], recipient, attempt+1)

			newEmail := *email
			newEmail.EnvelopeTo = []string{recipient}
			p.scheduleRetry(&newEmail, attempt+1)
		} else {
			l.Logger.Printf("[%s] Invalid recipient <%s>: %s\n",
				email.Headers["Subject"], recipient, errStr)
		}
	}
}

func (p *EmailWorkerPool) scheduleRetry(email *Email, attempt uint) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		l.Logger.Printf("[%s] Retry after %f seconds\n", email.Headers["Subject"], math.Pow(2, float64(attempt)))

		select {
		case <-time.After(delay):
			p.Submit(email, attempt)
		case <-p.quit:
			// TODO: implement saving state (e.g. to disk/redis to restore terminated jobs)
			l.Logger.Printf("[%s] Retry cancelled due to shutdown\n", email.Headers["Subject"])
		}
	}()
}

func (p *EmailWorkerPool) buildRawEmail(email *Email) string {
	var builder strings.Builder

	for k, v := range email.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", strings.TrimSpace(k), strings.TrimSpace(v)))
	}
	builder.WriteString("\r\n")
	builder.WriteString(strings.TrimSpace(email.Body))

	return builder.String()
}
