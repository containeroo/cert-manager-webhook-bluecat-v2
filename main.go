package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

const (
	defaultBlueCatAPIPath = "/api/v2"
	defaultTXTRecordTTL   = int64(120)
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	client kubernetes.Interface
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	APIHost               string                    `json:"apiHost"`
	APIPath               string                    `json:"apiPath,omitempty"`
	View                  string                    `json:"view,omitempty"`
	Zone                  string                    `json:"zone,omitempty"`
	ZoneID                int64                     `json:"zoneID,omitempty"`
	TTL                   int64                     `json:"ttl,omitempty"`
	QuickDeploy           *bool                     `json:"quickDeploy,omitempty"`
	Username              string                    `json:"username,omitempty"`
	InsecureSkipTLSVerify bool                      `json:"insecureSkipTLSVerify,omitempty"`
	PasswordSecretRef     *cmmeta.SecretKeySelector `json:"passwordSecretRef,omitempty"`
	BasicAuthSecretRef    *cmmeta.SecretKeySelector `json:"basicAuthSecretRef,omitempty"`
	BearerTokenSecretRef  *cmmeta.SecretKeySelector `json:"bearerTokenSecretRef,omitempty"`
	CABundleSecretRef     *cmmeta.SecretKeySelector `json:"caBundleSecretRef,omitempty"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "bluecat-address-manager"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if c.client == nil {
		return errors.New("kubernetes client is not initialized")
	}

	ctx := context.Background()
	cl, err := c.newBlueCatClient(ctx, ch.ResourceNamespace, cfg)
	if err != nil {
		return err
	}

	zoneID, err := c.resolveZoneID(ctx, cl, cfg, ch.ResolvedZone)
	if err != nil {
		return err
	}

	fqdn := normalizeDNSName(ch.ResolvedFQDN)
	zoneName := c.resolveZoneName(cfg, ch.ResolvedZone)
	relativeName := toRelativeName(fqdn, zoneName)

	records, err := cl.findMatchingTXTRecords(ctx, zoneID, fqdn, relativeName, ch.Key)
	if err != nil {
		return err
	}
	if len(records) > 0 {
		if !isQuickDeployEnabled(cfg) {
			return nil
		}
		recordIDs, err := extractRecordIDs(records)
		if err != nil {
			return err
		}
		return cl.triggerQuickDeploy(ctx, zoneID, recordIDs)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultTXTRecordTTL
	}
	payload := map[string]any{
		"type":         "TXTRecord",
		"name":         relativeName,
		"absoluteName": fqdn,
		"ttl":          ttl,
		"text":         ch.Key,
		"rdata":        quoteTXTValue(ch.Key),
	}

	_, _, err = cl.doJSON(ctx, http.MethodPost, fmt.Sprintf("/zones/%d/resourceRecords", zoneID), nil, payload, nil, http.StatusCreated, http.StatusOK, http.StatusConflict)
	if err != nil {
		return err
	}

	if !isQuickDeployEnabled(cfg) {
		return nil
	}

	records, err = cl.findMatchingTXTRecords(ctx, zoneID, fqdn, relativeName, ch.Key)
	if err != nil {
		return err
	}
	recordIDs, err := extractRecordIDs(records)
	if err != nil {
		return err
	}
	return cl.triggerQuickDeploy(ctx, zoneID, recordIDs)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if c.client == nil {
		return errors.New("kubernetes client is not initialized")
	}

	ctx := context.Background()
	cl, err := c.newBlueCatClient(ctx, ch.ResourceNamespace, cfg)
	if err != nil {
		return err
	}

	zoneID, err := c.resolveZoneID(ctx, cl, cfg, ch.ResolvedZone)
	if err != nil {
		return err
	}

	fqdn := normalizeDNSName(ch.ResolvedFQDN)
	zoneName := c.resolveZoneName(cfg, ch.ResolvedZone)
	relativeName := toRelativeName(fqdn, zoneName)

	records, err := cl.findMatchingTXTRecords(ctx, zoneID, fqdn, relativeName, ch.Key)
	if err != nil {
		return err
	}
	deletedRecordIDs := make([]int64, 0, len(records))

	for _, rr := range records {
		recordID, err := parseObjectID(rr)
		if err != nil {
			return err
		}
		_, _, err = cl.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/resourceRecords/%d", recordID), nil, nil, nil, http.StatusNoContent, http.StatusOK, http.StatusNotFound)
		if err != nil {
			return err
		}
		deletedRecordIDs = append(deletedRecordIDs, recordID)
	}

	if !isQuickDeployEnabled(cfg) {
		return nil
	}

	return cl.triggerQuickDeploy(ctx, zoneID, deletedRecordIDs)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func validateConfig(cfg customDNSProviderConfig) error {
	if strings.TrimSpace(cfg.APIHost) == "" {
		return errors.New("bluecat config apiHost is required")
	}
	if cfg.BearerTokenSecretRef == nil && cfg.BasicAuthSecretRef == nil && (strings.TrimSpace(cfg.Username) == "" || cfg.PasswordSecretRef == nil) {
		return errors.New("bluecat credentials are required: configure bearerTokenSecretRef, basicAuthSecretRef, or username + passwordSecretRef")
	}
	return nil
}

func (c *customDNSProviderSolver) newBlueCatClient(ctx context.Context, namespace string, cfg customDNSProviderConfig) (*bluecatClient, error) {
	baseURL, err := resolveAPIBaseURL(cfg.APIHost, cfg.APIPath)
	if err != nil {
		return nil, err
	}

	httpClient, err := c.buildHTTPClient(ctx, namespace, cfg)
	if err != nil {
		return nil, err
	}

	authHeader, err := c.resolveAuthorizationHeader(ctx, namespace, cfg, httpClient, baseURL)
	if err != nil {
		return nil, err
	}

	return &bluecatClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		authHeader: authHeader,
	}, nil
}

func (c *customDNSProviderSolver) buildHTTPClient(ctx context.Context, namespace string, cfg customDNSProviderConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.InsecureSkipTLSVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CABundleSecretRef != nil {
		caBytes, err := c.readSecretBytes(ctx, namespace, cfg.CABundleSecretRef)
		if err != nil {
			return nil, err
		}
		caPool := x509.NewCertPool()
		if ok := caPool.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("failed to parse ca bundle from caBundleSecretRef")
		}
		tlsConfig.RootCAs = caPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

func (c *customDNSProviderSolver) resolveAuthorizationHeader(
	ctx context.Context,
	namespace string,
	cfg customDNSProviderConfig,
	httpClient *http.Client,
	baseURL string,
) (string, error) {
	if cfg.BearerTokenSecretRef != nil {
		token, err := c.readSecretString(ctx, namespace, cfg.BearerTokenSecretRef)
		if err != nil {
			return "", err
		}
		return "Bearer " + strings.TrimSpace(token), nil
	}

	if cfg.BasicAuthSecretRef != nil {
		cred, err := c.readSecretString(ctx, namespace, cfg.BasicAuthSecretRef)
		if err != nil {
			return "", err
		}
		return "Basic " + normalizeBasicCredential(cred), nil
	}

	password, err := c.readSecretString(ctx, namespace, cfg.PasswordSecretRef)
	if err != nil {
		return "", err
	}

	credentials, err := loginSession(ctx, httpClient, baseURL, cfg.Username, password)
	if err != nil {
		return "", err
	}
	return credentials, nil
}

func normalizeBasicCredential(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, ":") {
		return base64.StdEncoding.EncodeToString([]byte(trimmed))
	}
	return trimmed
}

func loginSession(ctx context.Context, httpClient *http.Client, baseURL, username, password string) (string, error) {
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/sessions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("bluecat session auth failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bluecat session auth failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var sessionResp map[string]any
	if err := json.Unmarshal(body, &sessionResp); err != nil {
		return "", fmt.Errorf("bluecat session auth response decode failed: %w", err)
	}

	if creds := mapString(sessionResp, "basicAuthenticationCredentials"); creds != "" {
		return "Basic " + creds, nil
	}
	if token := mapString(sessionResp, "apiToken"); token != "" {
		return "Bearer " + token, nil
	}

	return "", errors.New("bluecat session auth response did not include basicAuthenticationCredentials or apiToken")
}

func resolveAPIBaseURL(host, apiPath string) (string, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return "", errors.New("apiHost is empty")
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid apiHost: %w", err)
	}

	pathPart := strings.TrimSpace(apiPath)
	if pathPart == "" {
		if parsed.Path == "" || parsed.Path == "/" {
			pathPart = defaultBlueCatAPIPath
		} else {
			pathPart = parsed.Path
		}
	}
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	parsed.Path = path.Clean(pathPart)
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return strings.TrimRight(parsed.String(), "/"), nil
}

func (c *customDNSProviderSolver) readSecretString(ctx context.Context, namespace string, sel *cmmeta.SecretKeySelector) (string, error) {
	value, err := c.readSecretBytes(ctx, namespace, sel)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (c *customDNSProviderSolver) readSecretBytes(ctx context.Context, namespace string, sel *cmmeta.SecretKeySelector) ([]byte, error) {
	if sel == nil {
		return nil, errors.New("secret reference is nil")
	}
	if strings.TrimSpace(namespace) == "" {
		return nil, errors.New("challenge request namespace is empty")
	}

	secretName := strings.TrimSpace(sel.Name)
	if secretName == "" {
		return nil, errors.New("secret reference name is empty")
	}
	if strings.TrimSpace(sel.Key) == "" {
		return nil, fmt.Errorf("secret %s key is empty", secretName)
	}

	secret, err := c.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to read secret %s/%s: %w", namespace, secretName, err)
	}
	data, ok := secret.Data[sel.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing key %s", namespace, secretName, sel.Key)
	}
	return data, nil
}

func (c *customDNSProviderSolver) resolveZoneID(ctx context.Context, cl *bluecatClient, cfg customDNSProviderConfig, challengeResolvedZone string) (int64, error) {
	if cfg.ZoneID > 0 {
		return cfg.ZoneID, nil
	}
	zoneName := c.resolveZoneName(cfg, challengeResolvedZone)
	zoneName = normalizeDNSName(zoneName)
	if zoneName == "" {
		return 0, errors.New("unable to resolve zone name from config or challenge")
	}
	return cl.resolveZoneID(ctx, zoneName, cfg.View)
}

func (c *customDNSProviderSolver) resolveZoneName(cfg customDNSProviderConfig, challengeResolvedZone string) string {
	if strings.TrimSpace(cfg.Zone) != "" {
		return cfg.Zone
	}
	return challengeResolvedZone
}

type bluecatClient struct {
	baseURL    string
	httpClient *http.Client
	authHeader string
}

type collectionResponse struct {
	Count int              `json:"count"`
	Data  []map[string]any `json:"data"`
	Links map[string]any   `json:"_links"`
}

type quickDeployAttempt struct {
	name  string
	body  any
}

func (c *bluecatClient) resolveZoneID(ctx context.Context, zoneName, viewName string) (int64, error) {
	filterCandidates := []string{
		fmt.Sprintf("name:eq('%s')", escapeFilterValue(zoneName)),
		fmt.Sprintf("absoluteName:eq('%s')", escapeFilterValue(zoneName)),
		fmt.Sprintf("absoluteName:eq('%s')", escapeFilterValue(zoneName+".")),
	}

	for _, filter := range filterCandidates {
		zones, err := c.listCollection(ctx, "/zones", filter)
		if err != nil {
			continue
		}
		zoneID, found, err := selectZoneID(zones, zoneName, viewName)
		if err != nil {
			return 0, err
		}
		if found {
			return zoneID, nil
		}
	}

	zones, err := c.listCollection(ctx, "/zones", "")
	if err != nil {
		return 0, err
	}
	zoneID, found, err := selectZoneID(zones, zoneName, viewName)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("zone %q not found in BlueCat", zoneName)
	}
	return zoneID, nil
}

func (c *bluecatClient) findMatchingTXTRecords(ctx context.Context, zoneID int64, fqdn, relativeName, key string) ([]map[string]any, error) {
	filterCandidates := []string{
		fmt.Sprintf("type:eq('TXTRecord') and absoluteName:eq('%s')", escapeFilterValue(fqdn)),
		fmt.Sprintf("type:eq('TXTRecord') and name:eq('%s')", escapeFilterValue(relativeName)),
	}

	for _, filter := range filterCandidates {
		records, err := c.listCollection(ctx, fmt.Sprintf("/zones/%d/resourceRecords", zoneID), filter)
		if err != nil {
			continue
		}
		matches := findTXTRecordMatches(records, fqdn, relativeName, key)
		if len(matches) > 0 {
			return matches, nil
		}
	}

	records, err := c.listCollection(ctx, fmt.Sprintf("/zones/%d/resourceRecords", zoneID), "")
	if err != nil {
		return nil, err
	}
	return findTXTRecordMatches(records, fqdn, relativeName, key), nil
}

func (c *bluecatClient) triggerQuickDeploy(ctx context.Context, zoneID int64, recordIDs []int64) error {
	attempts := buildQuickDeployAttempts(zoneID, recordIDs)
	if len(attempts) == 0 {
		return nil
	}

	errorsByAttempt := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		_, _, err := c.doJSON(
			ctx,
			http.MethodPost,
			"/deployments",
			nil,
			attempt.body,
			nil,
			http.StatusAccepted,
			http.StatusCreated,
			http.StatusOK,
		)
		if err == nil {
			return nil
		}
		errorsByAttempt = append(errorsByAttempt, fmt.Sprintf("%s: %v", attempt.name, err))
	}

	return fmt.Errorf("failed to trigger BlueCat quick deploy: %s", strings.Join(errorsByAttempt, " | "))
}

func (c *bluecatClient) listCollection(ctx context.Context, endpointPath, filter string) ([]map[string]any, error) {
	const pageSize = 250
	var out []map[string]any

	for offset := 0; ; offset += pageSize {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(pageSize))
		query.Set("offset", strconv.Itoa(offset))
		if strings.TrimSpace(filter) != "" {
			query.Set("filter", filter)
		}

		var page collectionResponse
		_, _, err := c.doJSON(ctx, http.MethodGet, endpointPath, query, nil, &page, http.StatusOK)
		if err != nil {
			return nil, err
		}
		if len(page.Data) == 0 {
			break
		}
		out = append(out, page.Data...)
		if page.Count > 0 && len(out) >= page.Count {
			break
		}
		if len(page.Data) < pageSize {
			break
		}
	}

	return out, nil
}

func (c *bluecatClient) doJSON(
	ctx context.Context,
	method string,
	endpointPath string,
	query url.Values,
	body any,
	out any,
	expectedStatus ...int,
) (int, []byte, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + endpointPath
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return 0, nil, err
	}
	if query != nil {
		parsed.RawQuery = query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	if !statusAllowed(resp.StatusCode, expectedStatus) {
		return resp.StatusCode, respBody, fmt.Errorf("bluecat api %s %s returned %d: %s", method, endpointPath, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, respBody, fmt.Errorf("failed to decode bluecat response for %s %s: %w", method, endpointPath, err)
		}
	}

	return resp.StatusCode, respBody, nil
}

func statusAllowed(status int, allowed []int) bool {
	for _, allowedStatus := range allowed {
		if status == allowedStatus {
			return true
		}
	}
	return false
}

func isQuickDeployEnabled(cfg customDNSProviderConfig) bool {
	if cfg.QuickDeploy == nil {
		return true
	}
	return *cfg.QuickDeploy
}

func extractRecordIDs(records []map[string]any) ([]int64, error) {
	ids := make([]int64, 0, len(records))
	for _, record := range records {
		id, err := parseObjectID(record)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func buildQuickDeployAttempts(zoneID int64, recordIDs []int64) []quickDeployAttempt {
	ids := dedupePositiveIDs(recordIDs)
	attempts := make([]quickDeployAttempt, 0, 8)

	if len(ids) > 0 {
		attempts = append(attempts,
			quickDeployAttempt{
				name: "selective-deploy-properties-string",
				body: map[string]any{
					"entityIds":  ids,
					"properties": "scope=specific|services=DNS",
				},
			},
			quickDeployAttempt{
				name: "selective-deploy-properties-map",
				body: map[string]any{
					"entityIds": ids,
					"properties": map[string]any{
						"scope":    "specific",
						"services": "DNS",
					},
				},
			},
			quickDeployAttempt{
				name: "selective-deploy-string-ids",
				body: map[string]any{
					"entityIds":  idsToStrings(ids),
					"properties": "scope=specific|services=DNS",
				},
			},
		)
	}

	if zoneID > 0 {
		attempts = append(attempts,
			quickDeployAttempt{
				name: "quick-deploy-zone-entityId",
				body: map[string]any{
					"entityId":   zoneID,
					"properties": "services=DNS",
				},
			},
			quickDeployAttempt{
				name: "quick-deploy-zone-entityIds",
				body: map[string]any{
					"entityIds":  []int64{zoneID},
					"properties": "services=DNS",
				},
			},
			quickDeployAttempt{
				name: "quick-deploy-zone-empty-properties",
				body: map[string]any{
					"entityId":   zoneID,
					"properties": "",
				},
			},
		)
	}

	return attempts
}

func dedupePositiveIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func idsToStrings(ids []int64) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.FormatInt(id, 10))
	}
	return out
}

func selectZoneID(zones []map[string]any, zoneName, viewName string) (int64, bool, error) {
	var matched []int64
	for _, zone := range zones {
		if !matchesZoneName(zone, zoneName) {
			continue
		}
		if strings.TrimSpace(viewName) != "" && !matchesViewName(zone, viewName) {
			continue
		}
		id, err := parseObjectID(zone)
		if err != nil {
			return 0, false, err
		}
		matched = append(matched, id)
	}

	if len(matched) == 0 {
		return 0, false, nil
	}
	if len(matched) > 1 {
		return 0, false, fmt.Errorf("zone %q matched multiple zone IDs, set view or zoneID explicitly", zoneName)
	}
	return matched[0], true, nil
}

func findTXTRecordMatches(records []map[string]any, fqdn, relativeName, key string) []map[string]any {
	matches := make([]map[string]any, 0)
	for _, rr := range records {
		if !matchesTXTType(rr) {
			continue
		}
		if !matchesRecordName(rr, fqdn, relativeName) {
			continue
		}
		if !matchesTXTValue(rr, key) {
			continue
		}
		matches = append(matches, rr)
	}
	return matches
}

func matchesTXTType(record map[string]any) bool {
	recordType := strings.ToLower(mapString(record, "type"))
	switch recordType {
	case "txt", "txtrecord":
		return true
	default:
		return false
	}
}

func matchesRecordName(record map[string]any, fqdn, relativeName string) bool {
	possible := []string{
		normalizeDNSName(mapString(record, "absoluteName")),
		normalizeDNSName(mapString(record, "fqdn")),
		normalizeDNSName(mapString(record, "name")),
	}

	targetAbsolute := normalizeDNSName(fqdn)
	targetRelative := normalizeDNSName(relativeName)
	for _, value := range possible {
		if value == "" {
			continue
		}
		if value == targetAbsolute || value == targetRelative {
			return true
		}
	}
	return false
}

func matchesTXTValue(record map[string]any, key string) bool {
	target := unquoteTXTValue(key)
	candidates := []string{
		mapString(record, "text"),
		mapString(record, "txt"),
		mapString(record, "rdata"),
		mapString(record, "data"),
	}
	for _, candidate := range candidates {
		if unquoteTXTValue(candidate) == target {
			return true
		}
	}
	return false
}

func matchesZoneName(record map[string]any, zoneName string) bool {
	target := normalizeDNSName(zoneName)
	candidates := []string{
		normalizeDNSName(mapString(record, "name")),
		normalizeDNSName(mapString(record, "absoluteName")),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if candidate == target {
			return true
		}
	}
	return false
}

func matchesViewName(record map[string]any, viewName string) bool {
	target := strings.EqualFold(strings.TrimSpace(viewName), strings.TrimSpace(mapString(record, "viewName")))
	if target {
		return true
	}
	viewObj, ok := record["view"].(map[string]any)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(viewName), strings.TrimSpace(mapString(viewObj, "name")))
}

func parseObjectID(record map[string]any) (int64, error) {
	idValue, ok := record["id"]
	if !ok {
		return 0, errors.New("bluecat response object missing id")
	}
	switch v := idValue.(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case string:
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid bluecat id value %q", v)
		}
		return id, nil
	default:
		return 0, fmt.Errorf("unsupported bluecat id type %T", idValue)
	}
}

func mapString(obj map[string]any, key string) string {
	raw, found := obj[key]
	if !found || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

func normalizeDNSName(name string) string {
	return strings.Trim(strings.TrimSpace(name), ".")
}

func toRelativeName(fqdn, zone string) string {
	fqdn = normalizeDNSName(fqdn)
	zone = normalizeDNSName(zone)
	if fqdn == "" {
		return fqdn
	}
	if zone == "" {
		return fqdn
	}
	if fqdn == zone {
		return "@"
	}
	suffix := "." + zone
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}
	return fqdn
}

func quoteTXTValue(value string) string {
	sanitized := strings.ReplaceAll(value, "\\", "\\\\")
	sanitized = strings.ReplaceAll(sanitized, "\"", "\\\"")
	return `"` + sanitized + `"`
}

func unquoteTXTValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, `"`)
	trimmed = strings.TrimSuffix(trimmed, `"`)
	return strings.ReplaceAll(trimmed, `\"`, `"`)
}

func escapeFilterValue(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
