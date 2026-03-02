package malako

import (
	"fmt"
	"log"
	"net/smtp"
)

func (m *Malakocut) SendEmail(subject, body string) {
	cfg := m.Config
	if cfg.SMTPHost == "" || cfg.SMTPUser == "" || cfg.SMTPPass == "" {
		log.Printf("[!] SMTP not configured. Logged alert: %s - %s", subject, body)
		return
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	// RFC 822 format: Headers followed by a blank line and then the body
	msg := "To: themikeschiffman@gmail.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n"

	err := smtp.SendMail(addr, auth, cfg.SMTPUser, []string{"themikeschiffman@gmail.com"}, []byte(msg))
	if err != nil {
		log.Printf("[!] Failed to send email alert: %v", err)
	} else {
		log.Printf("[*] Email alert sent: %s", subject)
	}
}
