package malako

import (
	"bytes"
	"log"
	"net/http"
	"time"

	"github.com/segmentio/encoding/json"
)

const (
	SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"
)

type sgMail struct {
	Personalizations []sgPers `json:"personalizations"`
	From             sgAddr   `json:"from"`
	Subject          string   `json:"subject"`
	Content          []sgCont `json:"content"`
}

type sgPers struct {
	To []sgAddr `json:"to"`
}

type sgAddr struct {
	Email string `json:"email"`
}

type sgCont struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (m *Malakocut) SendEmail(subject, body string) {
	if m.Config.SendGridKey == "" || m.Config.MailFrom == "" || m.Config.MailTo == "" {
		log.Printf("[!] Mail not fully configured. Logged alert: %s - %s", subject, body)
		return
	}

	payload := sgMail{
		Personalizations: []sgPers{{To: []sgAddr{{Email: m.Config.MailTo}}}},
		From:             sgAddr{Email: m.Config.MailFrom},
		Subject:          subject,
		Content:          []sgCont{{Type: "text/plain", Value: body}},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[!] Failed to marshal email payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", SENDGRID_URL, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[!] Failed to create email request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+m.Config.SendGridKey)
	req.Header.Set("Content-Type", "application/json")

	// Use a 5-second timeout for email sends
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[!] Failed to send email via SendGrid: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[!] SendGrid API error: status %d", resp.StatusCode)
	} else {
		log.Printf("[*] Email alert sent via SendGrid: %s", subject)
	}
}
