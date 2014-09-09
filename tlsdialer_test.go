package tlsdialer

import (
	"crypto/tls"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/keyman"
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
				log.Printf("Unable to accept!: %s", err)
				continue
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
	if err != nil {
		t.Errorf("Unable to dial: %s", err.Error())
	}
	serverName := <-receivedServerNames
	if serverName != "localhost" {
		t.Errorf("Unexpected ServerName on server: %s", serverName)
	}
}

func TestOKWithoutServerName(t *testing.T) {
	config := &tls.Config{
		RootCAs: cert.PoolContainingCert(),
	}
	_, err := Dial("tcp", ADDR, false, config)
	if err != nil {
		t.Errorf("Unable to dial: %s", err.Error())
	}
	serverName := <-receivedServerNames
	if serverName != "" {
		t.Errorf("Unexpected ServerName on server: %s", serverName)
	}
	if config.InsecureSkipVerify {
		t.Errorf("Original config shouldn't have been modified, but it was")
	}
}

func TestOKWithInsecureSkipVerify(t *testing.T) {
	_, err := Dial("tcp", ADDR, false, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Errorf("Unable to dial: %s", err.Error())
	}
	serverName := <-receivedServerNames
	if serverName != "" {
		t.Errorf("Unexpected ServerName on server: %s", serverName)
	}
}

func TestNotOKWithServerName(t *testing.T) {
	_, err := Dial("tcp", ADDR, true, nil)
	if err == nil {
		t.Error("There should have been a problem dialing")
	} else {
		if !strings.Contains(err.Error(), CERTIFICATE_ERROR) {
			t.Errorf("Wrong error on dial: %s", err)
		}
	}
}

func TestNotOKWithoutServerName(t *testing.T) {
	_, err := Dial("tcp", ADDR, false, nil)
	if err == nil {
		t.Error("There should have been a problem dialing")
	} else {
		if !strings.Contains(err.Error(), CERTIFICATE_ERROR) {
			t.Errorf("Wrong error on dial: %s", err)
		}
	}
}
