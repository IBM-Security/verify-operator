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
    "net/http/httputil"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

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

    store      *LruStore
}

/*****************************************************************************/

/*
 * This function is used to start the OIDC Server, and then wait until
 * we are told to terminate.
 */

func (server *OidcServer) start() {

    server.clients    = make(map[string]OidcClient)
    server.clientLock = &sync.RWMutex{}

    server.store = NewLruStore([]byte(securecookie.GenerateRandomKey(32)))

    server.log.Info("Starting the OIDC server.", "Port", httpsPort)

    /*
     * Load the certificate and keyfile.
     */

    cert, err := ioutil.ReadFile(server.cert)

    if err != nil {
        server.log.Error(err, "Failed to load the server certificate.")

        return
    }

    key, err := ioutil.ReadFile(server.key)

    if err != nil {
        server.log.Error(err, "Failed to load the server key.")

        return
    }

    /*
     * Define the http server and server handler.
     */

    pair, err := tls.X509KeyPair(cert, key)

    if err != nil {
        server.log.Error(err, "Failed to generate the X509 key pair.")

        return
    }

    server.web = &http.Server{
        Addr:      fmt.Sprintf(":%v", httpsPort),
        TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
    }

    mux := http.NewServeMux()

    mux.HandleFunc(checkUri,  server.check)
    mux.HandleFunc(authUri,   server.authenticate)
    mux.HandleFunc(loginUri,  server.login)
    mux.HandleFunc(logoutUri, server.logout)

    server.web.Handler = mux

    /*
     * Start listening for requests in a different thread.
     */

    server.log.Info("Waiting for Web requests.")

    go func() {
        if err := server.web.ListenAndServeTLS("", "");
                        err != http.ErrServerClosed {
            server.log.Error(err, "Failed to start the OIDC server.")
        }
    }()

    /*
     * Wait and listen for the OS shutdown singal.
     */

    signalChan := make(chan os.Signal, 1)

    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
        <-signalChan

    server.log.Info("Received a shutdown signal, shutting down the OIDC " +
                    "server gracefully.")

    server.web.Shutdown(context.Background())
}

/*****************************************************************************/

/*
 * This function is used to check to see if the user has already been 
 * authenticated.
 */

func (server *OidcServer) check(w http.ResponseWriter, r *http.Request) {

    status := http.StatusUnauthorized

    /*
     * Retrieve the session for the user.
     */

    session, err := server.store.Get(r, sessionCookieName)
    user         := ""

    if err == nil {
        /*
         * See if the session has expired.
         */

        val := session.Values[expiryKey]

        expiry, ok := val.(int64); 

        if ok && expiry > time.Now().Unix() {
            /*
             * Validate whether we have been authenticated or not.
             */

            user = server.GetSessionData(session, sessionUserKey)

            if user != "" {
                w.Header().Set("X-Username", user)

                identity := server.GetSessionData(session, sessionIdTokenKey)

                if identity != "" {
                    w.Header().Set(idTokenHdr, identity)
                }

                status = http.StatusNoContent
            }
        }
    }

    if status == http.StatusNoContent {
        server.log.Info("User is authenticated.", 
                "user", user, "forwarded", r.Header.Get("Forwarded"))
    } else {
        server.log.Info("Received a request from an unauthenticated user.",
                        "forwarded", r.Header.Get("Forwarded"))
    }

    w.WriteHeader(status)
}

/*****************************************************************************/

/*
 * This function is used to authenticate the user.  
 */

func (server *OidcServer) authenticate(w http.ResponseWriter, r *http.Request) {

    /*
     * Retrieve the session for the user.
     */

    session, err := server.store.Get(r, sessionCookieName)
    location     := "unknown"
    state        := "unknown"

    if err != nil {
        session = sessions.NewSession(server.store, sessionCookieName)
    } else {
        location = server.GetSessionData(session, sessionUrlKey)
        state    = server.GetSessionData(session, sessionStateKey)
    }

    /*
     * Create the logger to be used for this request.
     */

    logger := server.createLogger(location, state, r)

    logger.Log(5, "Received an authentication request.")

    if logger.currentLevel >= 9 {
        req, err := httputil.DumpRequest(r, true)  
        if err == nil {
            logger.Log(9, "Received an authentication request.", 
                                "request", string(req))
        }
    }

    /*
     * Check to see if this is an OIDC authentication request (determined
     * by the presence of the 'code' query string argument.
     */

    code := r.URL.Query().Get("code")

    if code == "" {

        /*
         * If we don't have an authorization code we bomb out now.
         */

        server.log.Info("No authorization code was provided with the request.")

        http.Error(w, "No authorization code was provided with the request.",
                        http.StatusBadRequest)

        return
    }

    logger.Log(7, "Received an authentication code.", "code", code)

    /*
     * Retrieve the Verify client which is to be used for this request.
     */

    client, err := server.getClient(logger, r)

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

    if r.URL.Query().Get("state") != state {
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

    logger.Log(6, "Successfully exchanged the code for a token.")

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

    logger.Log(7, "Successfully verified the token.", "token", rawIDToken)

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

    logger.Log(6, "Extracted the user name from the token.", 
                                    "user", claims.PreferredUsername)

    /*
     * Save the session information.
     */

    session.Values[sessionUserKey] = claims.PreferredUsername

    if server.includeIdToken(r) {
        session.Values[sessionIdTokenKey] = rawIDToken;
    }

    lifetime := server.sessionLifetime(r)

    session.Values[expiryKey] = time.Now().Unix() + int64(lifetime)
    session.Options.MaxAge    = lifetime

    delete(session.Values, sessionStateKey)

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

    if location == "" {
        http.Error(w, "The original URL is missing from the session data.", 
                        http.StatusInternalServerError)

        return
    }

    logger.Log(1, "User has been authenticated.", 
                        "user", claims.PreferredUsername,
                        "original.url", location)

    http.Redirect(w, r, location, http.StatusFound)
}

/*****************************************************************************/

/*
 * This function is used as the kick-off URL for the authentication process.
 * It will mostly involve redirecting the user to Verify for authentication.
 */

func (server *OidcServer) login(w http.ResponseWriter, r *http.Request) {

    origUrl := r.URL.Query().Get(urlArg)

    /*
     * Generate a uuid which will be used as the state value.
     */

    uuid, err := uuid.NewRandom()

    if err != nil {
        server.log.Error(err, "Failed to generate a new UUID.")

        http.Error(w, err.Error(), http.StatusInternalServerError)

        return
    }

    state := uuid.String()

    /*
     * Create the logger to be used for this request.
     */

    logger := server.createLogger(origUrl, state, r)

    if logger.currentLevel >= 9 {
        req, err := httputil.DumpRequest(r, true)  
        if err == nil {
            logger.Log(9, "Received an authentication request.", 
                                "request", string(req))
        }
    }

    logger.Log(5, "Kicking off the authentication process.")

    /*
     * Store the state value in a new cookie based session.
     */

    session, err := server.store.Get(r, sessionCookieName)

    if err != nil {
        session = sessions.NewSession(server.store, sessionCookieName)
    }

    session.Values[sessionStateKey] = uuid.String()

    /*
     * Store the original URL in the session.
     */

    session.Values[sessionUrlKey] = origUrl

    /*
     * Save the session.
     */

    session.Options.MaxAge = server.sessionLifetime(r)

    err = session.Save(r, w)

    if err != nil {
        server.log.Error(err, "Failed to store the session.")

        http.Error(w, err.Error(), http.StatusInternalServerError)

        return
    }

    /*
     * Retrieve the Verify client which is to be used for this request.
     */

    client, err := server.getClient(logger, r)

    if err != nil {
        server.log.Error(err, "Failed to retrieve the verify client.")

        http.Error(w, "Failed to retrieve the Verify client: " + err.Error(), 
                        http.StatusInternalServerError)

        return
    }

    /*
     * Return the redirect to the Verify OP.
     */

    location := client.oauth2Config.AuthCodeURL(state)

    logger.Log(6, "Sending a redirect to Verify for authentication.", 
                                                "location", location)

    http.Redirect(w, r, location, http.StatusFound)
}

/*****************************************************************************/

/*
 * This function is used log the user out.  As a result of this the user will 
 * be removed from the session cache and the session cookie will be cleared.
 */

func (server *OidcServer) logout(w http.ResponseWriter, r *http.Request) {
    /*
     * Retrieve the session for the user.
     */

    session, err := server.store.Get(r, sessionCookieName)

    if err == nil && session != nil {
        server.log.Info("Logging out the user.", 
                "user", server.GetSessionData(session, sessionUserKey))

        /*
         * Log out the user session by setting the MaxAge of the session to
         * -1.
         */

        session.Options.MaxAge = -1
        session.Save(r, w)
    } else {
        server.log.Info(
                "A logout has been received, but no user session is available.")
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

func (server *OidcServer) getClient(logger *LogInfo, r *http.Request) (
                        oidcClient *OidcClient, err error) {
    oidcClient = nil
    err        = nil

    logger.Log(6, "Attempting to retrieve a client to handle the request.")

    /*
     * Retrieve the name of the verify secret to be used from the request.  The
     * secret name is used as a key into our list of clients.
     */

    secretName := r.Header.Get(verifySecretHdr)

    if secretName == "" {
        err = errors.New("No Verify secret was provided in the request!")

        return
    }

    logger.Log(7, "Retrieving the secret for the client.", "name", secretName)

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

        logger.Log(6, 
            "No existing client was found and so creating a new handle now.",
            "namespace", namespaceName,
            "url.root", urlRoot,
            "secret", secretName)

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

            value, err = GetSecretData(client_.secret, field.name)

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

/*
 * Retrieve the maximum lifetime of a session.
 */

func (server *OidcServer) sessionLifetime(r *http.Request) (sessLifetime int) {
    sessLifetime  = defSessLifetime
    hdrString    := r.Header.Get(sessLifetimeHdr)

    if hdrString != "" {
        if val, err := strconv.Atoi(hdrString); err == nil {
            sessLifetime = val
        }
    }

    return
}

/*****************************************************************************/

/*
 * Should we include the identity token in the session?
 */

func (server *OidcServer) includeIdToken(r *http.Request) (include bool) {
    include    = false
    hdrString := r.Header.Get(idTokenHdr)

    if hdrString == "yes" {
        include = true
    }

    return
}
/*****************************************************************************/

/*
 * Create a logger based on the current request.
 */

func (server *OidcServer) createLogger(
                            location string, 
                            state    string, 
                            r        *http.Request) (logger *LogInfo) {

    hdrVal     := r.Header.Get(debugLevelHdr)
    debugLevel := 0

    if hdrVal != "" {
        if val, err := strconv.Atoi(hdrVal); err != nil {
            server.log.Error(err, "An invalid debug level was supplied.",
                                    "level", hdrVal)
        } else {
            debugLevel = val
        }
    }

    logger = &LogInfo { 
        currentLevel: debugLevel,
        log:          &server.log,
        attributes:   []interface{} { 
            "location", location,
            "state",    state,
        },
    }

    return
}

/*****************************************************************************/

