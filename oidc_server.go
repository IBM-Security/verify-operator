/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package main

/*
 * This file contains the logic which is used to handle the OIDC authentication
 * for the Verify Operator.
 */

/*****************************************************************************/

import (
    "context"
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "os"
    "os/signal"
    "net/http"
    "syscall"

    "github.com/go-logr/logr"
)

/*****************************************************************************/

type OidcServer struct {
    log  logr.Logger
    web  *http.Server
    cert string
    key  string
}

/*****************************************************************************/

/*
 * This function is used to start the OIDC Server, and then wait until
 * we are told to terminate.
 */

func (server *OidcServer) start() {

    httpsPort := 7443

    server.log.Info("Starting the OIDC server", "Port", httpsPort)

    /*
     * Load the certificate and keyfile.
     */

    cert, err := ioutil.ReadFile(server.cert)

    if err != nil {
        server.log.Error(err, "Failed to load the server certificate")

        return
    }

    key, err := ioutil.ReadFile(server.key)

    if err != nil {
        server.log.Error(err, "Failed to load the server key")

        return
    }

    /*
     * Define the http server and server handler.
     */

    pair, err := tls.X509KeyPair(cert, key)

    if err != nil {
        server.log.Error(err, "Failed to generate the X509 key pair")

        return
    }

    server.web = &http.Server{
        Addr:      fmt.Sprintf(":%v", httpsPort),
        TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
    }

    mux := http.NewServeMux()

    mux.HandleFunc("/", server.serveRoot)

    server.web.Handler = mux

    /*
     * Start listening for requests in a different thread.
     */

    server.log.V(5).Info("Waiting for Web requests")

    go func() {
        if err := server.web.ListenAndServeTLS("", "");
                        err != http.ErrServerClosed {
            server.log.Error(err, "Failed to start the OIDC server")
        }
    }()

    /*
     * Wait and listen for the OS shutdown singal.
     */

    signalChan := make(chan os.Signal, 1)

    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
        <-signalChan

    server.log.Info("Received a shutdown signal, shutting down the OIDC " +
                    "server gracefully")

    server.web.Shutdown(context.Background())
}

/*****************************************************************************/

/*
 * This function is used to server the root of the web space.
 */

func (server *OidcServer) serveRoot(w http.ResponseWriter, r *http.Request) {

    server.log.Info("XXX: received HTTP request", "req", r.URL.Path)

    w.WriteHeader(http.StatusNoContent)
}

/*****************************************************************************/

