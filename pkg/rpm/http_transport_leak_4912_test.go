package rpm

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// countingListener wraps a net.Listener and tracks how many accepted
// connections are currently open, so a test can assert that a probe closes its
// TCP connection instead of parking it in an unowned keep-alive idle pool.
type countingListener struct {
	net.Listener
	mu   sync.Mutex
	open int
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.open++
	l.mu.Unlock()
	return &countingConn{Conn: c, l: l}, nil
}

func (l *countingListener) openCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open
}

type countingConn struct {
	net.Conn
	l    *countingListener
	once sync.Once
}

func (c *countingConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.open--
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

// TestProbeHTTPBodylessResponseNoConnLeak_4912 proves the HTTP RPM probe does
// not leak a keep-alive connection per bodyless (204) response. Each probe uses
// a fresh, unowned http.Transport with no idle-connection timeout; if the
// connection were returned to that transport's idle pool (the keep-alive
// default) it would stay open forever. The fix disables keep-alives (and drops
// idle connections on return), so every probe's connection closes.
//
// The assertion is that the server's open-connection count returns to zero
// after several 204 probes. Against the pre-fix code the connections stay
// pooled/open and the count never drains -> the test fails.
func TestProbeHTTPBodylessResponseNoConnLeak_4912(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bodyless response — the deterministic idle-pool return path.
		w.WriteHeader(http.StatusNoContent)
	}))
	cl := &countingListener{Listener: ts.Listener}
	ts.Listener = cl
	ts.Start()
	defer ts.Close()

	m := &Manager{}
	test := &config.RPMTest{Target: ts.URL}

	const probes = 4
	for i := 0; i < probes; i++ {
		rtt, err := m.probeHTTP(context.Background(), test, probeSockOpts{})
		if err != nil {
			t.Fatalf("probe %d: unexpected error: %v", i, err)
		}
		if rtt <= 0 {
			t.Fatalf("probe %d: rtt=%v, want > 0", i, rtt)
		}
	}

	// The probe closes its connection synchronously on return, but the server
	// side observes the close asynchronously; poll briefly for the count to
	// drain to zero.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cl.openCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server still has %d open connection(s) after %d bodyless probes — "+
		"the probe is leaking keep-alive connections", cl.openCount(), probes)
}
