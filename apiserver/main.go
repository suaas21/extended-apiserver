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

func main() {

    var proxy = false
    flag.BoolVar(&proxy, "proxy-request", proxy, "forward request to database apiserver")
    flag.Parse()
    //.....................................................................................
    // generate CA & Certificate
    // generate serverKey & Certificate
	caKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatalln(err)
	}

	cfg := cert.Config{
		CommonName:  "ca",
		Organization: []string{"org"},
	}

	caCert, err := cert.NewSelfSignedCACert(cfg, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	serverKey, _ := cert.NewPrivateKey()
	cfgs := cert.Config{
		CommonName:   "server-cert",
		Organization: []string{"server-org"},
		AltNames: cert.AltNames{
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCert, err := cert.NewSignedCert(cfgs, serverKey,caCert,caKey)
	if err != nil {
		log.Fatalln(err)
	}

	err = ioutil.WriteFile("ca.crt", cert.EncodeCertPEM(caCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("ca.key", cert.EncodePrivateKeyPEM(caKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("server.crt",cert.EncodeCertPEM(serverCert), 0644)
	if err != nil{
		log.Fatalln(err)
	}
	err = ioutil.WriteFile("server.key", cert.EncodePrivateKeyPEM(serverKey), 0644)
	if err != nil{
		log.Fatalln(err)
	}

	//.......................................................................................
	// generate request header CA & Certificate
	// and Combine them
	rhClientKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatalln(err)
	}
	cfgr := cert.Config{
		AltNames: cert.AltNames{
			DNSNames: []string{"apiserver"},
		},
	}

	rhClientCert, err := cert.NewSelfSignedCACert(cfgr, rhClientKey)
	if err != nil {
		log.Fatalln(err)
	}

	_ = ioutil.WriteFile("rh.crt", cert.EncodeCertPEM(rhClientCert), 0644)
	_ = ioutil.WriteFile("rh.key", cert.EncodePrivateKeyPEM(rhClientKey), 0644)

	rhCert, _ := tls.LoadX509KeyPair("rh.crt","rh.key")


    //........................................................................................
     easCACertPool := x509.NewCertPool()
     if proxy{
     	databaseCert, _ := ioutil.ReadFile("databaseServer.crt")
     	//print database Certificate
     	fmt.Println(string(databaseCert))
     	easCACertPool.AppendCertsFromPEM(databaseCert)
	 }
    //........................................................................................

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("apiserver"))
	})
	r.HandleFunc("/core/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w,"Resource: %v\n", vars["resource"])

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
			u.Host = "127.0.0.2:8443"
			fmt.Printf("forward request to %v\n", u.String())

			req, _ := http.NewRequest(r.Method, u.String(), nil)
			if len(r.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			resp, err := client.Do(req)
			if err != nil{
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "error %v\n", err.Error())
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(http.StatusOK)
			io.Copy(w, resp.Body)


		})
	}



	_= http.ListenAndServeTLS(":8443", "server.crt", "server.key", r)






}
