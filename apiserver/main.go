package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

func init(){
	//generate all key and certificate and save it in allcacert
	//.....................................................................................
	// main server
	// generate CA & Certificate
	// generate serverKey & Certificate
	caKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatalln(err)
	}
	cfg := cert.Config{
		CommonName:  "ca",
		Organization: []string{"ca-org"},
	}
	caCert, err := cert.NewSelfSignedCACert(cfg, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	// generate server key & cert
	serverKey, _ := cert.NewPrivateKey()
	cfgs := cert.Config{
		CommonName:   "main",
		Organization: []string{"main-org"},
		AltNames: cert.AltNames{
			DNSNames: []string{"main"},
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCert, err := cert.NewSignedCert(cfgs, serverKey,caCert,caKey)
	if err != nil {
		log.Fatalln(err)
	}

	//generate client key & Cert
	clientKey, _ := cert.NewPrivateKey()
	cfgc := cert.Config{
		CommonName:   "client",
		Organization: []string{"client-org"},
		AltNames: cert.AltNames{
			DNSNames: []string{"sagor"},
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert, err := cert.NewSignedCert(cfgc, clientKey,caCert,caKey)
	if err != nil {
		log.Fatalln(err)
	}

	//save in allcacert file
	err = ioutil.WriteFile("../allcacert/ca.crt", cert.EncodeCertPEM(caCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/ca.key", cert.EncodePrivateKeyPEM(caKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/server.crt",cert.EncodeCertPEM(serverCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/server.key", cert.EncodePrivateKeyPEM(serverKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/client.crt",cert.EncodeCertPEM(clientCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/client.key", cert.EncodePrivateKeyPEM(clientKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}

	//.......................................................................................
	//request header
	// generate request header key & Cert
	// and Combine them
	rhClientKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatalln(err)
	}
	cfgr := cert.Config{
		CommonName: "rh",
		AltNames: cert.AltNames{
			DNSNames: []string{"request"},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rhClientCert, err := cert.NewSignedCert(cfgr, rhClientKey, caCert, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	//save in allcacert file
	err = ioutil.WriteFile("../allcacert/rh.crt", cert.EncodeCertPEM(rhClientCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/rh.key", cert.EncodePrivateKeyPEM(rhClientKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}



	//........................................................................................

	//extended server
	caKeyd, _ := cert.NewPrivateKey()
	cfgd := cert.Config{
		CommonName:  "dbca",
		Organization: []string{"dbca-org"},
	}

	caCertd, _ := cert.NewSelfSignedCACert(cfgd, caKeyd)

	serverKeyd, _ := cert.NewPrivateKey()
	cfgsd := cert.Config{
		CommonName:   "extended",
		Organization: []string{"extended-org"},
		AltNames: cert.AltNames{
			IPs: []net.IP{net.ParseIP("127.0.0.2")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertd, _ := cert.NewSignedCert(cfgsd, serverKeyd,caCertd,caKeyd)

	//generate database client key & Cert
	dbclientKey, _ := cert.NewPrivateKey()
	cfgdb := cert.Config{
		CommonName:   "dbclient",
		Organization: []string{"dbclient-org"},
		AltNames: cert.AltNames{
			DNSNames: []string{"sagor-a"},
			IPs: []net.IP{net.ParseIP("127.0.0.2")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	dbclientCert, err := cert.NewSignedCert(cfgdb, dbclientKey,caCertd,caKeyd)
	if err != nil {
		log.Fatalln(err)
	}

	err = ioutil.WriteFile("../allcacert/db.crt", cert.EncodeCertPEM(caCertd), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/db.key", cert.EncodePrivateKeyPEM(caKeyd), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/dbclient.crt", cert.EncodeCertPEM(dbclientCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/dbclient.key", cert.EncodePrivateKeyPEM(dbclientKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/dbServer.crt",cert.EncodeCertPEM(serverCertd), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("../allcacert/dbServer.key", cert.EncodePrivateKeyPEM(serverKeyd), 0644)
	if err != nil{
		log.Fatalln(err)
	}

}

func main() {

    var proxy = false
    flag.BoolVar(&proxy, "send-proxy-request", proxy, "forward request to database apiserver")
    flag.Parse()

	 rhCert, _ := tls.LoadX509KeyPair("../allcacert/rh.crt","../allcacert/rh.key")
     easCACertPool := x509.NewCertPool()
     if proxy{
     	databaseCert, _ := ioutil.ReadFile("../allcacert/db.crt")
     	easCACertPool.AppendCertsFromPEM(databaseCert)
	 }
    //........................................................................................

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_,err := w.Write([]byte("apiserver"))
		if err != nil{
			log.Fatalln(err)
		}
	})
	r.HandleFunc("/core/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		_,err := fmt.Fprintf(w, "Resource: %v\n", vars["resource"])
		if err != nil{
			log.Fatalln(err)
		}

	})
	if proxy{
		r.HandleFunc("/database/{resource}", func(w http.ResponseWriter, r *http.Request) {
			tr := &http.Transport{
				MaxIdleConnsPerHost: 10,
				TLSClientConfig: &tls.Config{
				   Certificates: []tls.Certificate{rhCert},
				   RootCAs: easCACertPool,
				},

			}
			client := http.Client{
				Transport: tr,
				Timeout: time.Duration(30 * time.Second),
			}
			u := *r.URL
			u.Scheme = "https"
			u.Host = "127.0.0.2:1234"
			fmt.Printf("forward request to %v\n", u.String())

			req, err := http.NewRequest(r.Method, u.String(), nil)
			if err != nil{
				log.Fatalln(err)
			}
			if len(r.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			//spew.Dump(req.Header)
			resp, err := client.Do(req)
			if err != nil{
				w.WriteHeader(http.StatusInternalServerError)
				_,_ = fmt.Fprintf(w, "error %v\n", err.Error())
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(http.StatusOK)
			io.Copy(w, resp.Body)


		})
	}
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

	apiClientCAPool := x509.NewCertPool()

	clientCA, err := ioutil.ReadFile("../allcacert/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	apiClientCAPool.AppendCertsFromPEM(clientCA)
	tlsconfig.ClientCAs = apiClientCAPool

	srv := http.Server{
		Addr: "127.0.0.1:8443",
		Handler: r,
		TLSConfig: tlsconfig,
	}

	if err := srv.ListenAndServeTLS("../allcacert/server.crt", "../allcacert/server.key"); err != nil {
		log.Fatal(err)
	}
}
