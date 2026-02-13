<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# cert-manager BlueCat Webhook

This repository contains a cert-manager DNS01 webhook solver for BlueCat
Address Manager REST v2.

- Webhook solver name: `bluecat-address-manager`
- Helm chart: `deploy/bluecat-webhook`
- Default image repo (chart): `ghcr.io/containeroo/cert-manager-webhook-bluecat-v2`

BlueCat API docs:
https://docs.bluecatnetworks.com/r/Address-Manager-RESTful-v2-API-Guide/

## How It Works

cert-manager sends DNS01 challenge requests to this webhook API service.
The solver then:

1. Authenticates to BlueCat.
2. Resolves the target zone.
3. Creates a TXT record for `_acme-challenge.<domain>`.
4. Deletes only the matching TXT value during cleanup.

The webhook supports these auth modes:

- bearer token from Kubernetes secret
- basic auth from Kubernetes secret
- username + password secret (creates BlueCat session via `/api/v2/sessions`)

## Prerequisites

1. Kubernetes cluster.
2. cert-manager installed and running.
3. Access to BlueCat Address Manager REST v2 endpoint.
4. A DNS zone in BlueCat for the domains you will validate.
5. Permission to install cluster-scoped RBAC and APIService resources.

## Release Pipeline

GitHub Actions workflow: `.github/workflows/build.yml`

Trigger:

- push a tag matching `v*` (example: `v0.1.0`)

What it does:

1. Runs `go test ./...`
2. Runs GoReleaser (`.goreleaser.yaml`)
3. Builds and pushes multi-arch images to GHCR:
   - `ghcr.io/containeroo/cert-manager-webhook-bluecat-v2:<tag>`
   - `ghcr.io/containeroo/cert-manager-webhook-bluecat-v2:latest`

Release commands:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Install The Webhook

Install or upgrade from this repository checkout:

```bash
helm upgrade --install bluecat-webhook ./deploy/bluecat-webhook \
  --namespace cert-manager \
  --create-namespace \
  --set groupName=acme.bluecat.yourdomain.tld \
  --set image.repository=ghcr.io/containeroo/cert-manager-webhook-bluecat-v2 \
  --set image.tag=v0.1.0
```

Notes:

- `groupName` must be a DNS name you own. Keep it stable.
- The same `groupName` must be used in your Issuer/ClusterIssuer webhook stanza.

## BlueCat Solver Config

`webhook.config` supports:

| Field | Required | Description |
| --- | --- | --- |
| `apiHost` | yes | BlueCat base URL, example `https://bam.example.internal` |
| `apiPath` | no | REST base path, default `/api/v2` |
| `view` | no | BlueCat DNS view name (recommended when zone names overlap) |
| `zoneID` | no | Numeric BlueCat zone ID |
| `zone` | no | Zone name, example `example.com`; if omitted, cert-manager `resolvedZone` is used |
| `ttl` | no | TXT TTL in seconds, default `120` |
| `insecureSkipTLSVerify` | no | Skip TLS verification (avoid in production) |
| `caBundleSecretRef` | no | Secret ref for PEM CA bundle used to trust BlueCat TLS cert |
| `bearerTokenSecretRef` | one auth mode required | Secret ref containing bearer token |
| `basicAuthSecretRef` | one auth mode required | Secret ref containing either `username:password` or base64 basic credentials |
| `username` | one auth mode required | BlueCat username when using session login |
| `passwordSecretRef` | one auth mode required | Secret ref containing password when using session login |

Authentication requirement:

- configure exactly one of:
  - `bearerTokenSecretRef`
  - `basicAuthSecretRef`
  - `username` + `passwordSecretRef`

## Secrets

Create a secret for username/password session auth:

```bash
kubectl -n cert-manager create secret generic bluecat-auth \
  --from-literal=password='YOUR_BLUECAT_PASSWORD'
```

Create a secret for bearer token auth:

```bash
kubectl -n cert-manager create secret generic bluecat-token \
  --from-literal=token='YOUR_BLUECAT_TOKEN'
```

Create a secret for custom CA bundle:

```bash
kubectl -n cert-manager create secret generic bluecat-ca \
  --from-file=ca.crt=./bluecat-ca.pem
```

Namespace rules:

- For `Issuer`, the secret must be in the same namespace as the `Issuer`.
- For `ClusterIssuer`, the secret must be in cert-manager's cluster resource namespace (typically `cert-manager`).

## ClusterIssuer Example

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-bluecat
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-bluecat-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.bluecat.yourdomain.tld
            solverName: bluecat-address-manager
            config:
              apiHost: https://bam.example.internal
              apiPath: /api/v2
              view: internal
              zone: example.com
              ttl: 120
              username: cert-manager
              passwordSecretRef:
                name: bluecat-auth
                key: password
              # Optional custom CA:
              # caBundleSecretRef:
              #   name: bluecat-ca
              #   key: ca.crt
```

## Certificate Example

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-example-com
  namespace: default
spec:
  secretName: app-example-com-tls
  issuerRef:
    name: letsencrypt-bluecat
    kind: ClusterIssuer
  dnsNames:
    - app.example.com
```

## Verify Deployment

```bash
kubectl get apiservice | grep acme.bluecat.yourdomain.tld
kubectl -n cert-manager get deploy,po | grep bluecat-webhook
kubectl -n cert-manager logs deploy/bluecat-webhook
kubectl get challenges -A
kubectl get orders -A
```

## Troubleshooting

- `no such host` or timeout to BlueCat:
  - check `apiHost`, network policies, and DNS resolution from webhook pod.
- TLS errors to BlueCat:
  - provide `caBundleSecretRef` or correct server certificate chain.
- `secret ... not found`:
  - verify secret namespace and key names.
- zone not found:
  - set `zoneID`, or set `zone` + `view` explicitly.
- challenge stuck in pending:
  - inspect webhook pod logs and `Challenge` events.

## Testing Locally

Unit tests:

```bash
go test ./...
```

Integration conformance tests are tagged:

```bash
go test -tags=integration .
```

The integration test requires kubebuilder test assets (`etcd`, `kube-apiserver`,
`kubectl`) and environment variables used by cert-manager's test harness.
