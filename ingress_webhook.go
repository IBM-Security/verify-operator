/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "net/url"
    "strconv"
    "strings"

    "github.com/go-logr/logr"

    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

    ibmv1 "github.com/ibm-security/verify-operator/api/v1"
    apiv1  "k8s.io/api/core/v1"
    netv1  "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    
)

/*****************************************************************************/

// +kubebuilder:webhook:path=/mutate-v1-ingress,mutating=true,failurePolicy=fail,sideEffects=None,groups=networking.k8s.io,resources=ingresses,verbs=create;update,versions=v1,name=mingress.kb.io,admissionReviewVersions={v1,v1beta1}

/*****************************************************************************/

/*
 * Our annotator structure.
 */

type ingressAnnotator struct {
    client    client.Client
    log       logr.Logger
    decoder   *admission.Decoder
    namespace string
}

/*
 * The Security Verify endpoints.
 */

type Endpoints struct {
    RegistrationEndpoint string `json:"registration_endpoint"`
    TokenEndpoint        string `json:"token_endpoint"`
}

/*****************************************************************************/

/*
 * The main Nginx annotation.
 */

const nginxServerAnnotation = `%s
%s
%s
%s
`

const nginxCheckLocationAnnotation = `location = %s {
  internal;
  proxy_pass %s%s;
  proxy_pass_request_body off;

  proxy_set_header Content-Length "";
}
`

const nginxAuthLocationAnnotation = `location = %s {
  proxy_pass %s%s;

  proxy_set_header %s %s;
  proxy_set_header %s %s;
  proxy_set_header %s %d;
  proxy_set_header %s %s;
  proxy_set_header %s $scheme://$http_host%s;
  %s
}
`

const nginx401LocationAnnotation = `error_page 401 = @error401;

# If the user is not logged in, redirect them to the login URL
location @error401 {
  proxy_pass %s%s?%s=$scheme://$http_host$request_uri;

  proxy_set_header %s %s;
  proxy_set_header %s %s;
  proxy_set_header %s %d;
  proxy_set_header %s $scheme://$http_host%s;
  %s
}
`

const nginxLogoutLocationAnnotation = `location = %s/logout {
  proxy_pass %s/logout;

  proxy_set_header %s %s;
}
`

const nginxLocationAnnotation = `auth_request %s;
auth_request_set $auth_username $upstream_http_x_username;
proxy_set_header X-Remote-User $auth_username;
%s
`

const nginxIDTokenAnnotation = `auth_request_set $id_token $upstream_http_%s;
proxy_set_header %s $id_token;
`

/*****************************************************************************/

/*
 * The Handle() function is called whenever the ingress is created and is used
 * to add the correct annotations to the ingress.
 */

func (a *ingressAnnotator) Handle(
            ctx context.Context, req admission.Request) admission.Response {
    /*
     * Grab the ingress information.
     */

    ingress := &netv1.Ingress{}

    err := a.decoder.Decode(req, ingress)

    if err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }

    a.log.Info("Proccesing an Ingress definition", 
            "name", ingress.Name, "namespace", ingress.Namespace)

    /*
     * Early exit if there are no annotations present.
     */

    if ingress.Annotations == nil {
        return admission.Allowed("No annotations present.")
    }

    /*
     * Check see see whether we have been told to protect this Ingress
     * resource.  This is controlled by the presence of the
     * verify.ibm.com/app.name annotation.
     */

    appName, found := ingress.Annotations[appNameKey]

    if !found {
        return admission.Allowed(
                    fmt.Sprintf("No %s annotation present.", appNameKey))
    }

    /*
     * Work out the debug level.
     */

    debugLevel        := 0
    debugLevelStr, ok := ingress.Annotations[debugLevelKey]

    if ok {
        val, err := strconv.Atoi(debugLevelStr); 

        if err != nil {
            a.log.Error(err, "Failed to determine the debug level.", 
                "ingress", ingress.Name, "application")

            return admission.Errored(http.StatusBadRequest, err)
        }

        debugLevel = val
    }

    logger := LogInfo { 
        currentLevel: debugLevel,
        log:          &a.log,
        attributes:   []interface{} {
                        "ingress",     ingress.Name, 
                        "application", appName },
    }

    logger.Log(1, "Setting the debug level.", "level", debugLevel)

    /*
     * See if the secret has already been created for this application.
     */

    secret, err := a.LocateAppSecret(&logger, appName, ingress)

    if err != nil {
        logger.Error(err, "Failed to locate the application secret." )

        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * Retrieve the custom resource which should be used.
     */

    cr, err := a.RetrieveCR(&logger, ingress)

    if err != nil {
        logger.Error(err, "Failed to retrieve the custom resource name.")

        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * If the secret has not been located so we need to register the application
     * and create the secret now.
     */

    if secret == nil {
        secret, err = a.RegisterApplication(&logger, appName, cr, ingress)

        if err != nil {
            logger.Error(err, "Failed to register the application.")

            return admission.Errored(http.StatusBadRequest, err)
        }
    }

    /*
     * Add the annotation to the ingress.
     */

    err = a.AddAnnotations(&logger, cr, ingress, secret.Namespace, secret.Name)

    if err != nil {
        logger.Error(err, 
                "Failed to add annotations to the Ingress definition.")

        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * Marshal and return the updated ingress definition.
     */

    marshaledIngress, err := json.Marshal(ingress)

    if err != nil {
        logger.Error(err, "Failed to marshal the Ingress definition.")

        return admission.Errored(http.StatusInternalServerError, err)
    }

    return admission.PatchResponseFromRaw(req.Object.Raw, marshaledIngress)
}

/*****************************************************************************/

/*
 * The LocateAppSecret function is used to search for the secret for the
 * specified application.
 */

func (a *ingressAnnotator) LocateAppSecret(
                logger  *LogInfo,
                appName string,
                ingress *netv1.Ingress) (*apiv1.Secret, error) {

    logger.Log(5, "Attempting to retrieve the secret for the Ingress resource.")

    /*
     * Check to see if the secret already exists.  We do this by searching
     * for a matching 'client_name' in all secrets which contain the 
     * 'product: ibm-security-verify' label.
     */

    secrets := &apiv1.SecretList{}

    err := a.client.List(
                context.TODO(), 
                secrets, 
                client.MatchingLabels {
                    productKey: productName,
                },
                client.InNamespace(ingress.Namespace),
            )

    if err != nil {
        return nil, err
    }

    found  := false
    secret := apiv1.Secret{}

    for _, secret = range secrets.Items {
        logger.Log(7, "Found a secret.", "secret", secret.Name)

        name, _ := GetSecretData(&secret, clientNameKey)

        logger.Log(7, "Checking the application name from the secret.", 
                            "name", name)

        if string(name) == appName {
            found = true

            break
        }
    }

    if ! found {
        return nil, nil
    }

    logger.Log(5, "Found a matching secret for the application.", 
                    "secret", secret.Name)

    /*
     * Now we need to ensure that the secret contains all of the required
     * fields.
     */

    err = a.ValidateSecret(logger, &secret)

    if err != nil {
        return nil, err
    }

    return &secret, nil
}

/*****************************************************************************/

/*
 * Valid that the secret has the required fields.
 */

func (a *ingressAnnotator) ValidateSecret(
                logger *LogInfo, secret *apiv1.Secret) (error) {
    logger.Log(5, "Validating the secret.", "secret", secret.Name)

    fields := []string {
        clientIdKey,
        clientSecretKey,
        discoveryEndpointKey,
    }

    for _, field := range fields {
        _, ok := secret.Data[field]

        if !ok {
            return errors.New(
                fmt.Sprintf("The secret, %s, is missing at " +
                    "least one required field: %s", secret.Name, field))
        }
    }

    return nil
}

/*****************************************************************************/

/*
 * The RegisterApplication function is used to register the new application
 * with IBM Security Verify.
 */

func (a *ingressAnnotator) RegisterApplication(
                    logger  *LogInfo,
                    appName string,
                    cr      *ibmv1.IBMSecurityVerify,
                    ingress *netv1.Ingress) (*apiv1.Secret, error) {

    logger.Log(5, "RegisterApplication", "annotations", ingress.Annotations)

    /*
     * Retrieve the app.url annotation.
     */

    appUrl, _ := ingress.Annotations[appUrlKey]

    /*
     * The client secret could either be in the namespace of the CR, or
     * included in the name specified in the CR.  We need to work out the
     * client secret name and namespace now.
     */

    var namespace  string
    var secretName string

    secretElements := strings.Split(cr.Spec.ClientSecret, "/")

    switch len(secretElements) {
        case 1:
            namespace  = cr.Namespace
            secretName = secretElements[0]
        case 2:
            namespace  = secretElements[0]
            secretName = secretElements[1]
        default:
            return nil, errors.New(fmt.Sprintf(
                    "An incorrectly formatted secret, %s, was specified",
                    cr.Spec.ClientSecret))
    }

    /*
     * Now that we have the appropriate custom resource we need to load the
     * corresponding secret.
     */

    clientSecret := &apiv1.Secret{}

    err := a.client.Get(context.TODO(), 
                client.ObjectKey{
                    Namespace: namespace,
                    Name:      secretName,
                }, 
                clientSecret)

    if err != nil {
        return nil, errors.New(
                fmt.Sprintf("The specified secret for the custom resource, " +
                    "%s, does not exist in the %s namespace.", 
                    secretName, namespace))
    }

    logger.Log(7, "Located the secret for the CR.", "secret", clientSecret.Name)

    err = a.ValidateSecret(logger, clientSecret)

    if err != nil {
        return nil, err
    }

    /*
     * Retrieve the endpoints for the verify tenant.
     */

    endpointUrl, err := GetSecretData(clientSecret, discoveryEndpointKey)

    if (err != nil) {
        return nil, err
    }

    endpoints, err := a.GetEndpoints(logger, endpointUrl)

    if err != nil {
        return nil, err
    }

    /*
     * Retrieve the access token which is to be used in the client
     * registration.
     */

    accessToken, err := a.GetAccessToken(
                            logger, endpoints.TokenEndpoint, clientSecret)

    if err != nil {
        return nil, err
    }

    /*
     * Now we can perform the registration with Verify.
     */

    return a.RegisterWithVerify(logger, cr, ingress, endpointUrl, appName, 
                        appUrl, endpoints.RegistrationEndpoint, accessToken)
}

/*****************************************************************************/

/*
 * The RetrieveCR function is used to retrieve the custom resource which
 * is to be used for the Ingress annotation.
 */

func (a *ingressAnnotator) RetrieveCR(
                    logger  *LogInfo,
                    ingress *netv1.Ingress) (*ibmv1.IBMSecurityVerify, error) {
    cr := &ibmv1.IBMSecurityVerify{}

    crName, found := ingress.Annotations[crNameKey]

    logger.Log(5, "Retrieving the CR", "name", crName)

    if ! found {
        logger.Log(5, 
            "The CR annotation was not found, using the first available CR.")

        /*
         * If the custom resource name was not specified we load the first
         * available custom resource.
         */

        crs := &ibmv1.IBMSecurityVerifyList{}

        err := a.client.List(
                    context.TODO(), 
                    crs,
                    client.InNamespace(ingress.Namespace),
                )

        if err != nil {
            return nil, err
        }

        if len(crs.Items) == 0 {
            return nil, errors.New(
                    "No IBMSecurityVerify custom resource has been created.")
        }

        cr = &crs.Items[0]

        logger.Log(5, "Located a CR to use.", "name", crName)
    } else {

        /*
         * The CR could either be in the namespace of the Ingress, or
         * included in the name specified in the annotation.  We need to work 
         * out the cr name and namespace now.
         */

        var namespace string

        nameElements := strings.Split(crName, "/")

        switch len(nameElements) {
            case 1:
                namespace  = ingress.Namespace
            case 2:
                namespace  = nameElements[0]
                crName     = nameElements[1]
        default:
            return nil, errors.New(fmt.Sprintf(
                "An incorrectly formatted custom resource, %s, was specified",
                crName))
        }

        err := a.client.Get(context.TODO(), 
                client.ObjectKey{
                    Namespace: namespace,
                    Name:      crName,
                }, 
                cr)

        if err != nil {
            return nil, errors.New(
                fmt.Sprintf("The verify.ibm.com/cr.name annotation, %s, does " +
                    "not correspond to an existing custom resource in the " +
                    "%s namespace.", crName, namespace))
        }
    }

    return cr, nil
}

/*****************************************************************************/

/*
 * The AddAnnotations function is used to add our annotations to the
 * supplied Ingress definition.
 */

func (a *ingressAnnotator) AddAnnotations(
                    logger    *LogInfo,
                    cr        *ibmv1.IBMSecurityVerify,
                    ingress   *netv1.Ingress,
                    namespace string,
                    name      string) (error) {

    logger.Log(5, "Adding the Verify annotations to the Ingress definition.")

    /*
     * Add the ingress class annotation.
     */

    if _, ok := ingress.Annotations["kubernetes.io/ingress.class"]; !ok {
        ingress.Annotations["kubernetes.io/ingress.class"] = "nginx"

        logger.Log(8, "Adding the ingress class annotation.",
                "kuberenetes.io/ingress.class", "nginx")
    }

    /*
     * Build up the ID Token annotation.
     */

    idTokenAnnotation := ""
    useIdToken        := "no"

    extIdTokenHdr, ok := ingress.Annotations[idTokenKey]

    if ok {
        idTokenAnnotation = fmt.Sprintf(nginxIDTokenAnnotation,
                                            idTokenHdr, extIdTokenHdr)
        useIdToken = "yes"
    }

    /*
     * Build up the debug level header.
     */

    debugLevelAnnotation := ""
    debugLevel, ok       := ingress.Annotations[debugLevelKey]

    if ok {
        debugLevelAnnotation = fmt.Sprintf("proxy_set_header %s %s;",
                                                debugLevelHdr, debugLevel)
    }

    /*
     * Add the location snippets for the Ingress resource.
     */

    checkPath := fmt.Sprintf("%s%s", cr.Spec.AuthPath, checkUri)

    ingress.Annotations["nginx.org/location-snippets"] = 
        fmt.Sprintf(nginxLocationAnnotation, checkPath, idTokenAnnotation)

    logger.Log(8, "Adding the location snippets.",
                "nginx.org/location-snippets", 
                ingress.Annotations["nginx.org/location-snippets"])

    /*
     * Add the server snippets for the Ingress resource.
     */

    oidcRoot := fmt.Sprintf("https://ibm-security-verify-operator-oidc-server" +
                            ".%s.svc.cluster.local:%d", a.namespace, httpsPort)

    checkAnnotations := fmt.Sprintf(nginxCheckLocationAnnotation,
            checkPath,                     // check location
            oidcRoot, checkUri,            // proxy_pass for the check call
        )

    authAnnotations := fmt.Sprintf(nginxAuthLocationAnnotation,
            cr.Spec.AuthPath,                         // authentication location
            oidcRoot, authUri,                        // proxy_pass 
            namespaceHdr, namespace,                  // namespace header
            verifySecretHdr, name,                    // verify secret header
            sessLifetimeHdr, cr.Spec.SessionLifetime, // sess lifetime header
            idTokenHdr, useIdToken,                   // use ID token header
            urlRootHdr, cr.Spec.AuthPath,             // URL root header
            debugLevelAnnotation,
        )

    unauthAnnotations := fmt.Sprintf(nginx401LocationAnnotation,
            oidcRoot, loginUri, urlArg,               // proxy_pass for the 401
            namespaceHdr, namespace,                  // namespace header
            verifySecretHdr, name,                    // verify secret header
            sessLifetimeHdr, cr.Spec.SessionLifetime, // sess lifetime header
            urlRootHdr, cr.Spec.AuthPath,             // URL root header
            debugLevelAnnotation,
        )

    logoutAnnotation := ""
    if cr.Spec.LogoutRedirectURL != "" {
        logoutAnnotation = fmt.Sprintf(nginxLogoutLocationAnnotation, 
            cr.Spec.AuthPath,                             // logout location
            oidcRoot,                                     // proxy_pass
            logoutRedirectHdr, cr.Spec.LogoutRedirectURL, // redirect header
        )
    }

    ingress.Annotations["nginx.org/server-snippets"]   = 
        fmt.Sprintf(nginxServerAnnotation, 
            checkAnnotations,
            authAnnotations,
            unauthAnnotations,
            logoutAnnotation,
        )

    logger.Log(8, "Adding the server snippets.",
                "nginx.org/server-snippets", 
                ingress.Annotations["nginx.org/server-snippets"])

    /*
     * Remove some existing annotations which are no longer required.
     */

    fields := []string {
        appNameKey,
        appUrlKey,
        crNameKey,
        consentKey,
        protocolKey,
        idTokenKey,
    }

    for _, field := range fields {
        delete(ingress.Annotations, field)
    }

    return nil
}

/*****************************************************************************/

/*
 * The InjectDecoder function injects the decoder.
 */

func (a *ingressAnnotator) InjectDecoder(d *admission.Decoder) error {
    a.decoder = d

    return nil
}

/*****************************************************************************/

/*
 * Retrieve the token endpoints based on the specified discovery URL.
 */

func (a *ingressAnnotator) GetEndpoints(
                    logger *LogInfo, discoveryUrl string) (*Endpoints, error) {

    logger.Log(5, "Retrieving the Verify endpoint.")

    /*
     * Construct the request.
     */

    request, err := http.NewRequest("GET", discoveryUrl, nil)

    if err != nil {
        return nil, err
    }

    request.Header.Add("Accept", "application/json")

    client := &http.Client{}

    /*
     * Send the request.
     */

    response, err := client.Do(request)

    if err != nil {
        return nil, err
    }

    if response.StatusCode != http.StatusOK {
        logger.Log(0, "Failed to retrieve the endpoints.", 
                        "url",    discoveryUrl,
                        "status", response.StatusCode,
                        "body",   response.Body)

        return nil, errors.New(
                        fmt.Sprintf("An unexpected response was received: %d", 
                        response.StatusCode))
    }

    /*
     * Parse the response.
     */

    var endpoints Endpoints

    err = json.NewDecoder(response.Body).Decode(&endpoints)

    if err != nil {
        return nil, err
    }

    logger.Log(7, "Located the verify endpoints.", "endpoints", endpoints)

    return &endpoints, nil
}

/*****************************************************************************/

/*
 * Retrieve the access token for the client.
 */

func (a *ingressAnnotator) GetAccessToken(
                                    logger   *LogInfo,
                                    tokenUrl string,
                                    secret   *apiv1.Secret) (string, error) {

    logger.Log(5, "Retrieving the access token for the client.", 
                        "token.url", tokenUrl, "secret", secret.Name)

    /*
     * Work out the client ID and secret to be used.
     */

    clientId, err := GetSecretData(secret, clientIdKey)

    if err != nil {
        return "", err
    }

    clientSecret, err := GetSecretData(secret, clientSecretKey)

    if err != nil {
        return "", err
    }

    logger.Log(7, "Located the client ID and secret.", "client.id", clientId,
                    "secret", "XXXXXX")

    /*
     * Set up the access token request.
     */

    data := url.Values{}

    data.Set("grant_type",    "client_credentials")
    data.Set("client_id",     clientId)
    data.Set("client_secret", clientSecret)
    data.Set("scope",         "openid")

    client := &http.Client{}

    request, err := http.NewRequest(
                            "POST", tokenUrl, strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }

    request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    request.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

    /*
     * Send the token request.
     */

    response, err := client.Do(request)

    if err != nil {
        return "", err
    }

    if response.StatusCode != http.StatusOK {
        logger.Log(0, "Failed to retrieve an access token.", 
                        "url",    tokenUrl,
                        "status", response.StatusCode,
                        "body",   response.Body)

        return "", errors.New(
                        fmt.Sprintf("An unexpected response was received: %d", 
                        response.StatusCode))
    }

    logger.Log(7, "Successfully retrieve the access token from Verify.")

    /*
     * Pull the token out of the response.
     */

    type VerifyGrantResponse struct {
        AccessToken string `json:"access_token"`
    }

    var jsonData VerifyGrantResponse

    err = json.NewDecoder(response.Body).Decode(&jsonData)

    if err != nil {
        return "", err
    }

    return jsonData.AccessToken, nil
}

/*****************************************************************************/

/*
 * Register the application with Verify.  This will also involve the 
 * creation of the secret which contains the registered credential information.
 */

func (a *ingressAnnotator) RegisterWithVerify(
                            logger            *LogInfo,
                            cr                *ibmv1.IBMSecurityVerify,
                            ingress           *netv1.Ingress,
                            discoveryEndpoint string,
                            appName           string,
                            appUrl            string,
                            registrationUrl   string,
                            accessToken       string) (*apiv1.Secret, error) {

    logger.Log(5, "Registering the application with Verify.", 
                "discovery", discoveryEndpoint, 
                "application.url", appUrl, "registration.url", registrationUrl)

    /*
     * Work out whether a consent action has been supplied.
     */

    consentAction, found := ingress.Annotations[consentKey]

    if !found {
        consentAction = defaultConsentAction
    }

    /*
     * Work out whether a protocol has been supplied.
     */

    protocol, found := ingress.Annotations[protocolKey]

    if !found {
        protocol = defaultProtocol
    } else {
        if protocol != "http" && protocol != "https" && protocol != "both" {
            return nil, errors.New(
                fmt.Sprintf("An unexpected protocol was specified: %s/%s", 
                        protocolKey, protocol))
        }
    }

    /*
     * Construct the request body.
     */

    type Request struct {
        ClientName       string   `json:"client_name"`
        RedirectUris     []string `json:"redirect_uris"`
        ConsentAction    string   `json:"consent_action"`
        AllUsersEntitled bool     `json:"all_users_entitled"`
        LoginUrl         string   `json:"initiate_login_uri,omitempty"`
        EnforcePkce      bool     `json:"enforce_pkce"`
    }

    /*
     * Construct the list of redirect URIs based on the Ingress specification.
     */

    var redirectUris []string

    if ingress.Spec.Rules != nil && len(ingress.Spec.Rules) > 0 {
        for _, rule := range ingress.Spec.Rules {
            if protocol == "http" || protocol == "both" {
                redirectUris = append(redirectUris, 
                        fmt.Sprintf("http://%s%s", rule.Host, cr.Spec.AuthPath))
            }

            if protocol == "https" || protocol == "both" {
                redirectUris = append(redirectUris, 
                    fmt.Sprintf("https://%s%s", rule.Host, cr.Spec.AuthPath))
            }
        }
    }

    /*
     * Construct the registration request.
     */

    body := &Request {
        ClientName:       appName,
        RedirectUris:     redirectUris,
        ConsentAction:    consentAction,
        AllUsersEntitled: true,
        LoginUrl:         appUrl,
        EnforcePkce:      false,
    }

    payloadBuf := new(bytes.Buffer)

    json.NewEncoder(payloadBuf).Encode(body)

    logger.Log(6, "Sending the request for the registration.", "body", body)

    /*
     * Set up the request.
     */

    request, err := http.NewRequest("POST", registrationUrl, payloadBuf)

    if err != nil {
        return nil, err
    }

    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Accept", "application/json")
    request.Header.Set("Authorization", "Bearer " + accessToken)

    /*
     * Make the request.
     */

    client := &http.Client{}

    response, err := client.Do(request)

    if err != nil {
        return nil, err
    }

    if response.StatusCode != http.StatusOK {
        logger.Log(0, "Failed to register the client.", 
                        "url",    registrationUrl,
                        "status", response.StatusCode,
                        "body",   response.Body)

        return nil, errors.New(
                        fmt.Sprintf("An unexpected response was received: %d", 
                        response.StatusCode))
    }

    /*
     * Process the response data.
     */

    type RegistrationResponse struct {
        ClientId     string `json:"client_id"`
        ClientSecret string `json:"client_secret"`
    }

    var jsonData RegistrationResponse

    err = json.NewDecoder(response.Body).Decode(&jsonData)

    if err != nil {
        return nil, err
    }

    logger.Log(5, "Successfully registered the application.")

    /*
     * Create the secret.
     */

    secretName := secretNamePrefix + jsonData.ClientId

    secret := &apiv1.Secret{
        Type: apiv1.SecretTypeOpaque,
        ObjectMeta: metav1.ObjectMeta {
            Name:      secretName,
            Namespace: ingress.Namespace,
            Labels:    map[string]string {
                productKey: productName,
            },
        },
        StringData: map[string]string{
            clientNameKey:        appName,
            clientIdKey:          jsonData.ClientId,
            clientSecretKey:      jsonData.ClientSecret,
            discoveryEndpointKey: discoveryEndpoint,
        },
    }

    logger.Log(6, "Creating the secret for the application.", 
                        "name", secretName)

    err = a.client.Create(context.TODO(), secret)

    if err != nil {
        return nil, err
    }

    return secret, nil
}

/*****************************************************************************/

