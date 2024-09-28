package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ct "github.com/google/certificate-transparency-go"
	"github.com/grantae/certinfo"
	"github.com/psanford/ssmparam/v2"
	"github.com/slack-go/slack"
)

func main() {
	lambda.Start(Handler)
}

var (
	prefix = "certs/"
)

func Handler(evt events.S3Event) error {
	lgr := slog.With()
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithDisableRequestCompression(aws.Bool(true)))
	if err != nil {
		return err
	}
	s3client := s3.NewFromConfig(cfg)

	ssmClient := ssm.NewFromConfig(cfg)

	kv := ssmparam.New(ssmClient)

	webhookURL, err := kv.Get("webhook_url")
	if err != nil {
		lgr.Error("get_webhook_url_err", "err", err)
	}

	for _, rec := range evt.Records {
		key := rec.S3.Object.Key
		if !strings.HasPrefix(key, prefix) {
			lgr.Info("skipping_file_outside_prefix", "key", key, "prefix", prefix)
			continue
		}

		key, err = url.PathUnescape(key)
		if err != nil {
			return err
		}

		resp, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &rec.S3.Bucket.Name,
			Key:    &key,
		})
		if err != nil {
			lgr.Error("get obj err", "key", key, "err", err)
			return err
		}

		dec := json.NewDecoder(resp.Body)
		var rawEntry ct.LeafEntry
		err = dec.Decode(&rawEntry)
		if err != nil {
			lgr.Error("decode json err", "key", key, "err", err)
			return err
		}

		resp.Body.Close()

		logEntry, err := ct.LogEntryFromLeaf(0, &rawEntry)
		if err != nil {
			lgr.Error("load log entry leaf err", "key", key, "err", err)
			return err
		}

		if logEntry.X509Cert == nil {
			lgr.Error("expected x509 cert but got none", "key", key)
			return nil
		}

		cert, err := x509.ParseCertificate(logEntry.X509Cert.Raw)
		if err != nil {
			lgr.Error("x509 parse err", "key", key, "err", err)
			return err
		}
		certInfoTxt, err := certinfo.CertificateText(cert)
		if err != nil {
			lgr.Error("cert txt err", "key", key, "err", err)
			return err
		}

		dnsNames := strings.Join(cert.DNSNames, ", ")
		messageText := fmt.Sprintf("*New Certificate Detected*\n\n"+
			"*Key:* %s\n"+
			"*DNS Names:* %s\n"+
			"*Not Before:* %s\n"+
			"*Not After:* %s\n\n"+
			"*Certificate Details:*\n```%s```",
			key,
			dnsNames,

			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339),
			certInfoTxt)

		err = slack.PostWebhook(webhookURL, &slack.WebhookMessage{
			Text: messageText,
		})
		if err != nil {
			lgr.Error("slack_webhook_err", "err", err)
		}
	}

	return nil
}
