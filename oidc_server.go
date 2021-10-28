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
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "os/signal"
    "net/http"
    "strings"
    "sync"
    "syscall"

    "github.com/coreos/go-oidc"
    "github.com/google/uuid"
    "github.com/gorilla/sessions"
    "github.com/gorilla/securecookie"
    "github.com/go-logr/logr"

    "golang.org/x/oauth2"

    "sigs.k8s.io/controller-runtime/pkg/client"

    apiv1  "k8s.io/api/core/v1"
)

/*****************************************************************************/

type OidcClient struct {
    secret       *apiv1.Secret
    oidcConfig   *oidc.Config
    provider     *oidc.Provider
    oauth2Config *oauth2.Config
}

type OidcServer struct {
    log        logr.Logger
    k8sClient  client.Client

    web        *http.Server
    cert       string
    key        string

    clients    map[string]OidcClient
    clientLock *sync.RWMutex

    store      *sessions.CookieStore
}

/*****************************************************************************/

/*
 * This function is used to start the OIDC Server, and then wait until
 * we are told to terminate.
 */

func (server *OidcServer) start() {

    server.clients    = make(map[string]OidcClient)
    server.clientLock = &sync.RWMutex{}

    server.store = sessions.NewCookieStore([]byte(
                                        securecookie.GenerateRandomKey(32)))

    server.store.MaxAge(sessionMaxAge)

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

    mux.HandleFunc(authUri,   server.authenticate)
    mux.HandleFunc(loginUri,  server.login)
    mux.HandleFunc(logoutUri, server.logout)

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
 * This function is used to authenticate the user.  
 */

func (server *OidcServer) authenticate(w http.ResponseWriter, r *http.Request) {

    server.log.Info("Received authentication request.")

    /*
     * Retrieve the session for the user.
     */

    session, err := server.store.Get(r, sessionCookieName)

    if err != nil {
        session = sessions.NewSession(server.store, sessionCookieName)
    }

    /*
     * Check to see if this is an OIDC authentication request (determined
     * by the presence of the 'code' query string argument.
     */

    code := r.URL.Query().Get("code")

    if code == "" {

        /*
         * This is not an authentication request and so we now need to see
         * if we have been authenticated or not.
         */

        user := server.GetSessionData(session, sessionUserKey)

        if user == "" {
            server.log.Info("User is not currently authorized.")

            w.WriteHeader(http.StatusUnauthorized)
        } else {
            server.log.Info("User is authorized.", "user", user)

            w.Header().Set("X-Username", user)
            w.WriteHeader(http.StatusNoContent)
        }

        return
    }

    /*
     * Retrieve the Verify client which is to be used for this request.
     */

    client, err := server.getClient(r)

    if err != nil {
        server.log.Error(err, "Failed to retrieve the verify client.")

        http.Error(w, "Failed to retrieve the Verify client: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    ctx      := context.Background()
    verifier := client.provider.Verifier(client.oidcConfig)

    /*
     * Validate the state ID matches the expected state.
     */

    if r.URL.Query().Get("state") != session.Values[sessionStateKey] {
        http.Error(w, "state did not match", http.StatusBadRequest)

        return
    }

    /*
     * Exchange with the provider the code for the OIDC token.
     */

    oauth2Token, err := client.oauth2Config.Exchange(ctx, code)

    if err != nil {
        server.log.Error(err, "Failed to exchange the token.")

        http.Error(w, "Failed to exchange token: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Extract the identity token.
     */

    rawIDToken, ok := oauth2Token.Extra("id_token").(string)

    if !ok {
        http.Error(w, "No id_token field in oauth2 token.", 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Verify the identity token.
     */

    idToken, err := verifier.Verify(ctx, rawIDToken)

    if err != nil {
        server.log.Error(err, "Failed to verify the token.")

        http.Error(w, "Failed to verify ID Token: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Extract the preferred username.
     */

    var claims struct {
	PreferredUsername string `json:"preferred_username"`
    }

    if err := idToken.Claims(&claims); err != nil {
        server.log.Error(err, "Failed to extract the claims.")

        http.Error(w, "Failed to extract the claims: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Save the user name to the session.
     */

    session.Values[sessionUserKey] = claims.PreferredUsername

    err = session.Save(r, w)

    if err != nil {
        server.log.Error(err, "Failed to save the session.")

        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    /*
     * We are now authenticated and need to redirect back to the originally
     * requested URL.
     */

    url := server.GetSessionData(session, sessionUrlKey)

    if url == "" {
        http.Error(w, "The original URL is missing from the session data.", 
                        http.StatusInternalServerError)

        return
    }

    server.log.Info("User has been authenticated.", 
                        "user", claims.PreferredUsername,
                        "original url", url)

    http.Redirect(w, r, url, http.StatusFound)
}

/*****************************************************************************/

/*
 * This function is used as the kick-off URL for the authentication process.
 * It will mostly involve redirecting the user to Verify for authentication.
 */

func (server *OidcServer) login(w http.ResponseWriter, r *http.Request) {

    server.log.Info("Kicking off the authentication process.")

    /*
     * Retrieve the Verify client which is to be used for this request.
     */

    client, err := server.getClient(r)

    if err != nil {
        server.log.Error(err, "Failed to retrieve the verify client.")

        http.Error(w, "Failed to retrieve the Verify client: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Generate a uuid which will be used as the state value.
     */

    uuid, err := uuid.NewRandom()

    if err != nil {
        server.log.Error(err, "Failed to generate a new UUID.")

        http.Error(w, err.Error(), http.StatusInternalServerError)

        return
    }

    /*
     * Store the state value in a new cookie based session.
     */

    session, err := server.store.Get(r, sessionCookieName)

    if err != nil {
        session = sessions.NewSession(server.store, sessionCookieName)
    }

    state := uuid.String()

    session.Values[sessionStateKey] = uuid.String()

    /*
     * Store the original URL in the session.
     */

    session.Values[sessionUrlKey] = r.URL.Query().Get(urlArg)

    /*
     * Save the session.
     */

    err = session.Save(r, w)

    if err != nil {
        server.log.Error(err, "Failed to store the session.")

        http.Error(w, err.Error(), http.StatusInternalServerError)

        return
    }

    /*
     * Return the redirect to the Verify OP.
     */

    http.Redirect(w, r, client.oauth2Config.AuthCodeURL(state), 
                        http.StatusFound)
}

/*****************************************************************************/

/*
 * This function is used log the user out.  As a result of this the user will 
 * be removed from the session cache and the session cookie will be cleared.
 */

func (server *OidcServer) logout(w http.ResponseWriter, r *http.Request) {
    server.log.Info("Logging out the user.")

    /*
     * Retrieve the session for the user.
     */

    session, err := server.store.Get(r, sessionCookieName)

    if err == nil && session != nil {
        /*
         * Log out the user session by setting the MaxAge of the session to
         * -1.
         */

        session.Options.MaxAge = -1
        session.Save(r, w)
    }

    logoutURL := r.Header.Get(logoutRedirectHdr)

    if logoutURL == "" {
        w.WriteHeader(http.StatusNoContent)
    } else {
        http.Redirect(w, r, logoutURL, http.StatusFound)
    }
}


/*****************************************************************************/

/*
 * This function is used to retrieve a client definition which can be used
 * for the specified request.  If a cached client definition is not found
 * a new client definition will be created.
 */

func (server *OidcServer) getClient(r *http.Request) (
                                        oidcClient *OidcClient, err error) {
    oidcClient = nil
    err        = nil

    /*
     * Retrieve the name of the verify secret to be used from the request.  The
     * secret name is used as a key into our list of clients.
     */

    secretName := r.Header.Get(verifySecretHdr)

    if secretName == "" {
        err = errors.New("No Verify secret was provided in the request!")

        return
    }

    server.clientLock.Lock()

    client_ := server.clients[secretName]

    if client_ == (OidcClient{}) {

        /*
         * Retrieve the namespace from the request.
         */

        namespaceName := r.Header.Get(namespaceHdr)

        if namespaceName == "" {
            server.clientLock.Unlock()

            err = errors.New("No namespace was provided in the request!")

            return
        }

        /*
         * Retrieve the URL root from the request.
         */

        urlRoot := r.Header.Get(urlRootHdr)

        if urlRoot == "" {
            server.clientLock.Unlock()

            err = errors.New("No URL root was provided in the request!")

            return
        }

        /*
         * Retrieve the client secret.
         */

        client_.secret = &apiv1.Secret{}

        err = server.k8sClient.Get(context.TODO(), 
                    client.ObjectKey{
                        Namespace: namespaceName,
                        Name:      secretName,
                    }, 
                    client_.secret)

        if err != nil {
            server.clientLock.Unlock()

            return
        }

        /*
         * Retrieve the required pieces of data from the secret.
         */

        type verify_secret struct {
            name  string
            value string
        }

        var secrets = []verify_secret {
            verify_secret {
                name: discoveryEndpointKey,
                value: "",
            },
            verify_secret {
                name: clientIdKey,
                value: "",
            },
            verify_secret {
                name: clientSecretKey,
                value: "",
            },
        }

        const endpointIdx     = 0
        const clientIdIdx     = 1
        const clientSecretIdx = 2

        for idx, field := range secrets {
            var value string

            value, err = server.GetSecretData(
                                    client_.secret, field.name)

            if err != nil {
                server.clientLock.Unlock()

                return
            }

            secrets[idx].value = value
        }

        /*
         * Create the provider.  This will also involve retrieving the provider
         * endpoints using the discovery URL.
         */

        ctx := context.Background()

        client_.provider, err = oidc.NewProvider(ctx, 
            strings.TrimSuffix(secrets[endpointIdx].value, 
                            "/.well-known/openid-configuration"))

        if err != nil {
            server.clientLock.Unlock()

            return
        }

        /*
         * Configure an OpenID Connect aware OAuth2 client.
         */

        client_.oauth2Config = &oauth2.Config{
            RedirectURL:  urlRoot,

            ClientID:     secrets[clientIdIdx].value,
            ClientSecret: secrets[clientSecretIdx].value,

            Endpoint:     client_.provider.Endpoint(),
            Scopes:       []string{oidc.ScopeOpenID},
        }

        /*
         * Create the OIDC configuration.
         */

        client_.oidcConfig = &oidc.Config{
            ClientID: secrets[clientIdIdx].value,
        }

        /*
         * Add the client to the cache.
         */

        server.clients[secretName] = client_
    } 

    server.clientLock.Unlock()

    oidcClient = &client_

    return 
}

/*****************************************************************************/

/*
 * Retrieve the base64 decoded piece of data from the supplied secret.
 */

func (server *OidcServer) GetSecretData(
                            secret *apiv1.Secret, name string) (string, error) {
    value, ok := secret.Data[name]

    if !ok {
        return "", errors.New(
                fmt.Sprintf("The field, %s, is not available in the " +
                    "secret: %s", name, secret.Name))
    }

    return strings.TrimSuffix(string(value), "\n"), nil
}

/*****************************************************************************/

/*
 * Retrieve the specified piece of session data as a string.
 */

func (server *OidcServer) GetSessionData(
                        session *sessions.Session, key string) (data string) {

    val := session.Values[key]

    var ok bool

    if data, ok = val.(string); !ok {
        data = ""
    }

    return
}

/*****************************************************************************/


