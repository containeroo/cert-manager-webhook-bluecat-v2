// package bluecatmock contains a self-contained DNS webhook used by tests.
// DNS conformance tests
package bluecatmock

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/miekg/dns"
	"k8s.io/client-go/rest"
)

type mockSolver struct {
	name       string
	server     *dns.Server
	txtRecords map[string]string
	sync.RWMutex
}

func (e *mockSolver) Name() string {
	return e.name
}

func (e *mockSolver) Present(ch *acme.ChallengeRequest) error {
	e.Lock()
	e.txtRecords[ch.ResolvedFQDN] = ch.Key
	e.Unlock()
	return nil
}

func (e *mockSolver) CleanUp(ch *acme.ChallengeRequest) error {
	e.Lock()
	delete(e.txtRecords, ch.ResolvedFQDN)
	e.Unlock()
	return nil
}

func (e *mockSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	if e.server.PacketConn == nil {
		conn, err := net.ListenPacket("udp", e.server.Addr)
		if err != nil {
			return err
		}
		e.server.PacketConn = conn
	}

	go func(done <-chan struct{}) {
		<-done
		if err := e.server.Shutdown(); err != nil {
			if isExpectedServerCloseError(err) {
				return
			}
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}(stopCh)
	go func() {
		if err := e.server.ActivateAndServe(); err != nil {
			if isExpectedServerCloseError(err) {
				return
			}
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}()
	return nil
}

func isExpectedServerCloseError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "server not started") || strings.Contains(msg, "closed network connection")
}

func New(port string) webhook.Solver {
	e := &mockSolver{
		name:       "bluecat-mock",
		txtRecords: make(map[string]string),
	}
	e.server = &dns.Server{
		Addr:    ":" + port,
		Net:     "udp",
		Handler: dns.HandlerFunc(e.handleDNSRequest),
	}
	return e
}
