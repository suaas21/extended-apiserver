package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"

	//"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {

	var proxy = false
	flag.BoolVar(&proxy, "receive-proxy-request", proxy, "receive forwarded requests from apiserver")
	flag.Parse()

	rhCaCertPool := x509.NewCertPool()
	if proxy{
		rhCert, err := ioutil.ReadFile("../allcacert/ca.crt")
		if err != nil{
			log.Fatalln(err)
		}
		rhCaCertPool.AppendCertsFromPEM(rhCert)
	}
	//....................................................................................................
	r := mux.NewRouter()
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, err := writer.Write([]byte("database-server"))
		log.Fatalln(err)
	})
	r.HandleFunc("/database/{resource}", func(w http.ResponseWriter, r *http.Request) {
		user := "system:anonymous"
		src := "-"
		if len(r.TLS.PeerCertificates) > 0 { // client TLS was used
			opts := x509.VerifyOptions{
				Roots:     rhCaCertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
				user = r.TLS.PeerCertificates[0].Subject.CommonName // user name from client cert
				src = "Client-Cert-CN"
			} else {
				user = r.Header.Get("X-Remote-User") // user name from header value passed by apiserver
				src = "X-Remote-User"
			}
		}

		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		_,err := fmt.Fprintf(w, "Resource abc: %v requested by user[%s]=%s\n", vars["resource"], src, user)
		if err != nil{
			log.Fatalln(err)
		}
	})

	tlsconfig := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		SessionTicketsDisabled:   true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		NextProtos: []string{"h2", "http/1.1"},
	}

	caCertPool := x509.NewCertPool()
	clientCA, err := ioutil.ReadFile("../allcacert/db.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(clientCA)
	if proxy{
		rhCert, err := ioutil.ReadFile("../allcacert/rh.crt")
		if err != nil{
		  log.Fatalln(err)
		}
		caCertPool.AppendCertsFromPEM(rhCert)
		caCert, err := ioutil.ReadFile("../allcacert/ca.crt")
		if err != nil{
		  log.Fatalln(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}
	tlsconfig.ClientCAs = caCertPool


	srv := http.Server{
		Addr: "127.0.0.2:1234",
		Handler: r,
		TLSConfig: tlsconfig,
	}

	if err := srv.ListenAndServeTLS("../allcacert/dbServer.crt", "../allcacert/dbServer.key"); err != nil{
		log.Fatalln(err)
	}
}