package tlsdialer

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/getlantern/keyman"
	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	certError = "x509: certificate signed by unknown authority"
	nameError = "x509: certificate is valid for localhost, not example.com"
)

func TestOKWithServerName(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	cwt, err := DialForTimings(net.DialTimeout, 30*time.Second, "tcp", sAddr, true, &tls.Config{
		RootCAs:    cert.PoolContainingCert(),
		ServerName: "localhost",
	})
	require.NoError(t, err, "Unable to dial")
	require.Equal(t, "localhost", <-serverNames, "Unexpected ServerName on server")
	require.NotNil(t, cwt.ResolvedAddr, "Should have resolved addr")

	closeAndCountFDs(t, cwt.Conn, err, fdc)
}

func TestOKWithServerNameAndChromeHandshake(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	d := &Dialer{
		DoDial:         net.DialTimeout,
		Timeout:        30 * time.Second,
		SendServerName: true,
		ClientHelloID:  tls.HelloChrome_Auto,
		Config: &tls.Config{
			RootCAs:    cert.PoolContainingCert(),
			ServerName: "localhost",
		},
	}
	cwt, err := d.DialForTimings("tcp", sAddr)
	require.NoError(t, err, "Unable to dial")
	require.Equal(t, "localhost", <-serverNames, "Unexpected ServerName on server")
	require.NotNil(t, cwt.ResolvedAddr, "Should have resolved addr")

	closeAndCountFDs(t, cwt.Conn, err, fdc)
}

func TestOKWithServerNameAndLongTimeout(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	conn, err := DialTimeout(net.DialTimeout, 25*time.Second, "tcp", sAddr, true, &tls.Config{
		RootCAs:    cert.PoolContainingCert(),
		ServerName: "localhost",
	})
	assert.NoError(t, err, "Unable to dial")
	assert.Equal(t, "localhost", <-serverNames, "Unexpected ServerName on server")

	closeAndCountFDs(t, conn, err, fdc)
}

func TestOKWithoutServerName(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	config := &tls.Config{
		RootCAs:    cert.PoolContainingCert(),
		ServerName: "localhost", // we manually set a ServerName to make sure it doesn't get sent
	}
	conn, err := Dial("tcp", sAddr, false, config)
	assert.NoError(t, err, "Unable to dial")
	assert.Empty(t, <-serverNames, "Unexpected ServerName on server")
	assert.False(t, config.InsecureSkipVerify, "Original config shouldn't have been modified, but it was")

	closeAndCountFDs(t, conn, err, fdc)
}

func TestOKWithInsecureSkipVerify(t *testing.T) {
	sAddr, _, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	conn, err := Dial("tcp", sAddr, false, &tls.Config{
		InsecureSkipVerify: true,
	})
	assert.NoError(t, err, "Unable to dial")
	<-serverNames

	closeAndCountFDs(t, conn, err, fdc)
}

func TestOKWithCustomClientHelloSpec(t *testing.T) {
	// This suite is unlikely to be chosen without our forcing it.
	const suite = tls.TLS_RSA_WITH_AES_256_CBC_SHA

	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	d := Dialer{
		DoDial: net.DialTimeout,
		Config: &tls.Config{
			RootCAs: cert.PoolContainingCert(),
		},
		ClientHelloID: tls.HelloCustom,
		ClientHelloSpec: &tls.ClientHelloSpec{
			CipherSuites: []uint16{suite},
			TLSVersMin:   tls.VersionTLS10,
			TLSVersMax:   tls.VersionTLS12,
		},
	}

	conn, err := d.Dial("tcp", sAddr)
	require.NoError(t, err)

	// Check that our custom spec was used.
	require.Equal(t, suite, conn.ConnectionState().CipherSuite)
	<-serverNames

	closeAndCountFDs(t, conn, err, fdc)
}

func TestNotOKWithServerName(t *testing.T) {
	sAddr, _, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	conn, err := Dial("tcp", sAddr, true, nil)
	require.Error(t, err, "There should have been a problem dialing")
	require.Contains(t, err.Error(), certError, "Wrong error on dial")
	<-serverNames

	closeAndCountFDs(t, conn, err, fdc)
}

func TestNotOKWithoutServerName(t *testing.T) {
	sAddr, _, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	conn, err := Dial("tcp", sAddr, false, &tls.Config{ServerName: "localhost"})
	require.Error(t, err, "There should have been a problem dialing")
	require.Contains(t, err.Error(), certError, "Wrong error on dial")
	assert.Empty(t, <-serverNames, "Unexpected ServerName on server")

	closeAndCountFDs(t, conn, err, fdc)
}

func TestNotOKWithBadRootCert(t *testing.T) {
	sAddr, _, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	badCert, err := keyman.LoadCertificateFromPEMBytes([]byte(GoogleInternetAuthority))
	require.NoError(t, err)

	conn, err := Dial("tcp", sAddr, true, &tls.Config{RootCAs: badCert.PoolContainingCert()})
	require.Error(t, err)
	assert.Error(t, err, "There should have been a problem dialing")
	require.Contains(t, err.Error(), certError, "Wrong error on dial")
	<-serverNames

	closeAndCountFDs(t, conn, err, fdc)
}

func TestSimulatedMITMDialingPublicSite(t *testing.T) {
	dialFn := func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, "www.microsoft.com:443", timeout)
	}
	connWithTimings, err := DialForTimings(dialFn, 30*time.Second, "tcp", "www.google.com:443", false, &tls.Config{})
	if !assert.Error(t, err, "Should get certificate validation failure when connecting to mismatched site") {
		connWithTimings.Conn.Close()
	}
}

func TestOKWithForceValidateName(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	d := &Dialer{
		DoDial:            net.DialTimeout,
		Timeout:           30 * time.Second,
		SendServerName:    true,
		ForceValidateName: "localhost",
		Config: &tls.Config{
			ServerName: "example.com",
			RootCAs:    cert.PoolContainingCert(),
		},
	}

	cwt, err := d.DialForTimings("tcp", sAddr)
	require.NoError(t, err, "Unable to dial")
	require.Equal(t, "example.com", <-serverNames, "Unexpected ServerName on server")
	require.NotNil(t, cwt.ResolvedAddr, "Should have resolved addr")

	closeAndCountFDs(t, cwt.Conn, err, fdc)
}

func TestNotOKWithoutForceValidateName(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	d := &Dialer{
		DoDial:         net.DialTimeout,
		Timeout:        30 * time.Second,
		SendServerName: true,
		Config: &tls.Config{
			ServerName: "example.com",
			RootCAs:    cert.PoolContainingCert(),
		},
	}
	cwt, err := d.DialForTimings("tcp", sAddr)
	require.Error(t, err, "There should have been a problem dialing")
	require.Contains(t, err.Error(), nameError, "Wrong error on dial")
	<-serverNames
	closeAndCountFDs(t, cwt.Conn, err, fdc)
}

func TestVariableTimeouts(t *testing.T) {
	sAddr, cert, serverNames := newTestServer(t)
	_, fdc, err := fdcount.Matching("TCP")
	require.NoError(t, err)

	// Timeouts can happen in different places, run a bunch of randomized trials
	// to try to cover all of them.
	_, fdc, err = fdcount.Matching("TCP")
	require.NoError(t, err)

	doTestTimeout := func(timeout time.Duration) (didTimeout bool, err error) {
		conn, err := DialTimeout(net.DialTimeout, timeout, "tcp", sAddr, false, &tls.Config{
			RootCAs: cert.PoolContainingCert(),
		})
		if err == nil {
			conn.Close()
			return false, nil
		}

		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			return true, nil
		}
		return false, err
	}

	// The 5000 microsecond limits is arbitrary. In some systems this may be too low/high.
	// The algorithm will try to adapt if connections succeed and will lower the current limit,
	// but it won't be allowed to timeout below the established lower boundary.
	timeoutMax := 5000
	numberOfTimeouts := 0
	for i := 0; i < 500; i++ {
		timeout := rand.Intn(timeoutMax) + 1
		didTimeout, err := doTestTimeout(time.Duration(timeout) * time.Microsecond)
		require.NoError(t, err)
		if didTimeout {
			numberOfTimeouts++
		} else {
			timeoutMax = int(float64(timeoutMax) * 0.75)
		}
	}
	assert.NotEqual(t, 0, numberOfTimeouts, "Should have timed out at least once")

	// Wait to give the sockets time to close
	time.Sleep(1 * time.Second)
	// Attempt to clean up and release any blocked goroutines.
Cleanup:
	for true {
		select {
		case <-serverNames:
		default:
			break Cleanup
		}
	}

	assert.NoError(t, fdc.AssertDelta(0), "Number of open files should be the same after test as before")
}

// The serverNames channel is used to communicate SNI values sent by clients.
func newTestServer(t *testing.T) (addr string, cert *keyman.Certificate, serverNames <-chan string) {
	t.Helper()

	pk, err := keyman.GeneratePK(2048)
	require.NoError(t, err)

	// Generate self-signed certificate
	cert, err = pk.TLSCertificateFor(time.Now().Add(1*time.Hour), true, nil, "tlsdialer", "localhost", "127.0.0.1")
	require.NoError(t, err)

	keypair, err := tls.X509KeyPair(cert.PEMEncoded(), pk.PEMEncoded())
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{keypair}})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	_serverNames := make(chan string)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				t.Log("test server failed to accept connection:", err)
			}
			go func() {
				tlsConn := conn.(*tls.Conn)
				// Discard this error, since we will use it for testing
				_ = tlsConn.Handshake()
				serverName := tlsConn.ConnectionState().ServerName
				if err := conn.Close(); err != nil {
					t.Log("test server failed to close connection")
				}
				_serverNames <- serverName
			}()
		}
	}()

	return listener.Addr().String(), cert, _serverNames
}

func closeAndCountFDs(t *testing.T, conn *tls.Conn, err error, fdc *fdcount.Counter) {
	if err == nil {
		if err := conn.Close(); err != nil {
			t.Fatalf("Unable to close connection: %v", err)
		}
	}
	assert.NoError(t, fdc.AssertDelta(0), "Number of open TCP files should be the same after test as before")
}

const GoogleInternetAuthority = `-----BEGIN CERTIFICATE-----
MIID8DCCAtigAwIBAgIDAjp2MA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwNQYDVR0fBC4wLDAqoCig
JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMC4GCCsGAQUF
BwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL2cuc3ltY2QuY29tMBcGA1UdIAQQ
MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQUFAAOCAQEAJ4zP6cc7vsBv6JaE
+5xcXZDkd9uLMmCbZdiFJrW6nx7eZE4fxsggWwmfq6ngCTRFomUlNz1/Wm8gzPn6
8R2PEAwCOsTJAXaWvpv5Fdg50cUDR3a4iowx1mDV5I/b+jzG1Zgo+ByPF5E0y8tS
etH7OiDk4Yax2BgPvtaHZI3FCiVCUe+yOLjgHdDh/Ob0r0a678C/xbQF9ZR1DP6i
vgK66oZb+TWzZvXFjYWhGiN3GhkXVBNgnwvhtJwoKvmuAjRtJZOcgqgXe/GFsNMP
WOH7sf6coaPo/ck/9Ndx3L2MpBngISMjVROPpBYCCX65r+7bU2S9cS+5Oc4wt7S8
VOBHBw==
-----END CERTIFICATE-----`
