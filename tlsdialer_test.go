package tlsdialer

import (
	"crypto/tls"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/getlantern/keyman"
	"github.com/getlantern/testify/assert"
)

const (
	ADDR              = "localhost:15623"
	CERTIFICATE_ERROR = "x509: certificate signed by unknown authority"
)

var (
	receivedServerNames = make(chan string)

	cert *keyman.Certificate
)

func init() {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		log.Fatalf("Unable to generate key: %s", err)
	}

	// Generate self-signed certificate
	cert, err = pk.TLSCertificateFor("tlsdialer", "localhost", time.Now().Add(1*time.Hour), true, nil)
	if err != nil {
		log.Fatalf("Unable to generate cert: %s", err)
	}

	keypair, err := tls.X509KeyPair(cert.PEMEncoded(), pk.PEMEncoded())
	if err != nil {
		log.Fatalf("Unable to generate x509 key pair: %s", err)
	}

	listener, err := tls.Listen("tcp", ADDR, &tls.Config{
		Certificates: []tls.Certificate{keypair},
	})

	if err != nil {
		log.Fatalf("Unable to listen: %s", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatalf("Unable to accept: %s", err)
			}
			go func() {
				tlsConn := conn.(*tls.Conn)
				tlsConn.Handshake()
				receivedServerNames <- tlsConn.ConnectionState().ServerName
			}()
		}
	}()
}

func TestOKWithServerName(t *testing.T) {
	_, err := Dial("tcp", ADDR, true, &tls.Config{
		RootCAs: cert.PoolContainingCert(),
	})
	assert.NoError(t, err, "Unable to dial")
	serverName := <-receivedServerNames
	assert.Equal(t, "localhost", serverName, "Unexpected ServerName on server")
}

func TestOKWithServerNameAndLongTimeout(t *testing.T) {
	_, err := DialWithDialer(&net.Dialer{
		Timeout: 25 * time.Second,
	}, "tcp", ADDR, true, &tls.Config{
		RootCAs: cert.PoolContainingCert(),
	})
	assert.NoError(t, err, "Unable to dial")
	serverName := <-receivedServerNames
	assert.Equal(t, "localhost", serverName, "Unexpected ServerName on server")
}

func TestOKWithoutServerName(t *testing.T) {
	config := &tls.Config{
		RootCAs: cert.PoolContainingCert(),
	}
	_, err := Dial("tcp", ADDR, false, config)
	assert.NoError(t, err, "Unable to dial")
	serverName := <-receivedServerNames
	assert.Empty(t, serverName, "Unexpected ServerName on server")
	assert.False(t, config.InsecureSkipVerify, "Original config shouldn't have been modified, but it was")
}

func TestOKWithInsecureSkipVerify(t *testing.T) {
	_, err := Dial("tcp", ADDR, false, &tls.Config{
		InsecureSkipVerify: true,
	})
	assert.NoError(t, err, "Unable to dial")
	serverName := <-receivedServerNames
	assert.Empty(t, serverName, "Unexpected ServerName on server")
}

func TestNotOKWithServerName(t *testing.T) {
	_, err := Dial("tcp", ADDR, true, nil)
	assert.Error(t, err, "There should have been a problem dialing")
	if err != nil {
		assert.Contains(t, err.Error(), CERTIFICATE_ERROR, "Wrong error on dial")
	}
}

func TestNotOKWithoutServerName(t *testing.T) {
	_, err := Dial("tcp", ADDR, false, nil)
	assert.Error(t, err, "There should have been a problem dialing")
	if err != nil {
		assert.Contains(t, err.Error(), CERTIFICATE_ERROR, "Wrong error on dial")
	}
}

func TestVariableTimeouts(t *testing.T) {
	// Timeouts can happen in different places, run a bunch of randomized trials
	// to try to cover all of them.
	for i := 0; i < 500; i++ {
		doTestTimeout(t, time.Duration(rand.Intn(5000)+1)*time.Microsecond)
	}
}

func doTestTimeout(t *testing.T, timeout time.Duration) {
	_, err := DialWithDialer(&net.Dialer{
		Timeout: timeout,
	}, "tcp", ADDR, false, nil)
	assert.Error(t, err, "There should have been a problem dialing", timeout)
	if err != nil {
		assert.True(t, err.(net.Error).Timeout(), "Dial error should be timeout", timeout)
	}
}
