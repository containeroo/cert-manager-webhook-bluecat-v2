package main

import (
	"testing"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestNormalizeBasicCredential(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already encoded",
			input: "YWRtaW46YWRtaW4=",
			want:  "YWRtaW46YWRtaW4=",
		},
		{
			name:  "username password",
			input: "admin:admin",
			want:  "YWRtaW46YWRtaW4=",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeBasicCredential(tc.input)
			if got != tc.want {
				t.Fatalf("normalizeBasicCredential(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveAPIBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		apiPath string
		want    string
	}{
		{
			name:    "default path",
			host:    "bam.example.internal",
			apiPath: "",
			want:    "https://bam.example.internal/api/v2",
		},
		{
			name:    "custom path",
			host:    "https://bam.example.internal",
			apiPath: "/api/v2",
			want:    "https://bam.example.internal/api/v2",
		},
		{
			name:    "host already has path",
			host:    "https://bam.example.internal/api/v2",
			apiPath: "",
			want:    "https://bam.example.internal/api/v2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAPIBaseURL(tc.host, tc.apiPath)
			if err != nil {
				t.Fatalf("resolveAPIBaseURL(%q, %q) returned error: %v", tc.host, tc.apiPath, err)
			}
			if got != tc.want {
				t.Fatalf("resolveAPIBaseURL(%q, %q) = %q, want %q", tc.host, tc.apiPath, got, tc.want)
			}
		})
	}
}

func TestToRelativeName(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		zone string
		want string
	}{
		{
			name: "record under zone",
			fqdn: "_acme-challenge.example.com.",
			zone: "example.com.",
			want: "_acme-challenge",
		},
		{
			name: "zone apex",
			fqdn: "example.com.",
			zone: "example.com.",
			want: "@",
		},
		{
			name: "zone mismatch",
			fqdn: "_acme-challenge.other.com.",
			zone: "example.com.",
			want: "_acme-challenge.other.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toRelativeName(tc.fqdn, tc.zone)
			if got != tc.want {
				t.Fatalf("toRelativeName(%q, %q) = %q, want %q", tc.fqdn, tc.zone, got, tc.want)
			}
		})
	}
}

func TestFindTXTRecordMatches(t *testing.T) {
	records := []map[string]any{
		{
			"id":           10,
			"type":         "TXTRecord",
			"absoluteName": "_acme-challenge.example.com",
			"rdata":        "\"token-1\"",
		},
		{
			"id":           11,
			"type":         "TXTRecord",
			"absoluteName": "_acme-challenge.example.com",
			"rdata":        "\"token-2\"",
		},
	}

	matches := findTXTRecordMatches(records, "_acme-challenge.example.com.", "_acme-challenge", "token-1")
	if len(matches) != 1 {
		t.Fatalf("expected 1 matching record, got %d", len(matches))
	}
}

func TestValidateConfig(t *testing.T) {
	valid := customDNSProviderConfig{
		APIHost:               "https://bam.example.internal",
		Zone:                  "example.com",
		Username:              "cert-manager",
		PasswordSecretRef:     secretRef("bluecat-auth", "password"),
		InsecureSkipTLSVerify: true,
	}

	if err := validateConfig(valid); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func secretRef(name, key string) *cmmeta.SecretKeySelector {
	return &cmmeta.SecretKeySelector{
		LocalObjectReference: cmmeta.LocalObjectReference{
			Name: name,
		},
		Key: key,
	}
}
