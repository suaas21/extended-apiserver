package main

import (
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"k8s.io/client-go/util/cert"
	"net"
	"net/http"
)

func main() {
	caKey, _ := cert.NewPrivateKey()

	cfg := cert.Config{
		CommonName:  "ca",
		Organization: []string{"org"},
	}

	caCert, _ := cert.NewSelfSignedCACert(cfg, caKey)

	serverKey, _ := cert.NewPrivateKey()
	cfgs := cert.Config{
		CommonName:   "server-cert",
		Organization: []string{"server-org"},
		AltNames: cert.AltNames{
			IPs: []net.IP{net.ParseIP("127.0.0.2")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCert, _ := cert.NewSignedCert(cfgs, serverKey,caCert,caKey)

	_ = ioutil.WriteFile("database.crt", cert.EncodeCertPEM(caCert), 0644)
	_ = ioutil.WriteFile("database.key", cert.EncodePrivateKeyPEM(caKey), 0644)
	_ = ioutil.WriteFile("databaseServer.crt",cert.EncodeCertPEM(serverCert), 0644)
	_ = ioutil.WriteFile("databaseServer.key", cert.EncodePrivateKeyPEM(serverKey), 0644)

	databaseCert, _ := ioutil.ReadFile("database.crt")
	fmt.Println(string(databaseCert))

	r := mux.NewRouter()
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("database-server"))
	})
	_= http.ListenAndServeTLS(":8443", "databaseServer.crt", "databaseServer.key", r)

}