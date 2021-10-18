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
    client  client.Client
    log     logr.Logger
    decoder *admission.Decoder
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
 * Constants....
 */

/*
 * Annotation keys.
 */

const appNameKey           = "verify.ibm.com/app.name"
const appUrlKey            = "verify.ibm.com/app.url"
const crNameKey            = "verify.ibm.com/cr.name"
const consentKey           = "verify.ibm.com/consent.action"

/*
 * Secret keys.
 */

const productKey           = "product"
const clientNameKey        = "client_name"
const clientIdKey          = "client_id"
const clientSecretKey      = "client_secret"
const discoveryEndpointKey = "discovery_endpoint"
const secretNamePrefix     = "ibm-security-verify-client-"
const productName          = "ibm-security-verify"

/*
 * Registration constants.
 */

const defaultConsentAction = "always_prompt"
const oidcAuthUri          = "/verify-oidc/auth"

/*
 * The main Nginx annotation.
 */

const nginxAnnotation = `location = /verify-oidc {
  internal;

  proxy_pass https://ibm-security-verify-operator/oidc;
  proxy_pass_request_body off;

  proxy_set_header Content-Length "";
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;

  # these return values are passed to the @error401 call
  auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
  auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
  auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;
}

error_page 401 = @error401;

# If the user is not logged in, redirect them to the login URL
location @error401 {
  return 302 https://ibm-security-verify-operator/verify-oidc/auth?url=https://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err&namespace=%s&verify-secret=%s;
}
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

    a.log.Info("Handle", "name", ingress.Name)

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
     * See if the secret has already been created for this application.
     */

    secret, err := a.LocateAppSecret(appName, ingress)

    if err != nil {
        a.log.Error(err, "Failed to locate the application secret.", 
                                                    "application", appName)

        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * If the secret has not been located so we need to register the application
     * and create the secret now.
     */

    if secret == nil {
        secret, err = a.RegisterApplication(appName, ingress)

        if err != nil {
            a.log.Error(err, "Failed to register the application.", 
                                                    "application", appName)

            return admission.Errored(http.StatusBadRequest, err)
        }
    }

    /*
     * Add the annotation to the ingress.
     */

    err = a.AddAnnotations(ingress, secret.Namespace, secret.Name)

    if err != nil {
        a.log.Error(err, 
                "Failed to add annotations to the Ingress definition.", 
                "ingress", ingress.Name, "application", appName)

        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * Marshal and return the updated ingress definition.
     */

    marshaledIngress, err := json.Marshal(ingress)

    if err != nil {
        a.log.Error(err, 
                "Failed to marshal the Ingress definition.", 
                "ingress", ingress.Name, "application", appName)

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
                appName string,
                ingress *netv1.Ingress) (*apiv1.Secret, error) {

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
        name, _ := a.GetSecretData(&secret, clientNameKey)

        if string(name) == appName {
            found = true

            break
        }
    }

    if ! found {
        return nil, nil
    }

    /*
     * Now we need to ensure that the secret contains all of the required
     * fields.
     */

    err = a.ValidateSecret(&secret)

    if err != nil {
        return nil, err
    }

    return &secret, nil
}

/*****************************************************************************/

/*
 * Valid that the secret has the required fields.
 */

func (a *ingressAnnotator) ValidateSecret(secret *apiv1.Secret) (error) {
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
                    appName string,
                    ingress *netv1.Ingress) (*apiv1.Secret, error) {

    a.log.Info("RegisterApplication", 
                    "name", appName, "annotations", ingress.Annotations)

    /*
     * Verify that the app.url annotation exists.
     */

    appUrl, found := ingress.Annotations[appUrlKey]

    if !found {
        return nil, errors.New(
            fmt.Sprintf("A required annotation, %s, is missing.", appUrlKey))
    }

    /*
     * Retrieve the custom resource which should be used.
     */

    cr, err := a.RetrieveCR(ingress)

    if err != nil {
        return nil, err
    }

    /*
     * Now that we have the appropriate custom resource we need to load the
     * corresponding secret.
     */

    clientSecret := &apiv1.Secret{}

    err = a.client.Get(context.TODO(), 
                client.ObjectKey{
                    Namespace: ingress.Namespace,
                    Name:      cr.Spec.ClientSecret,
                }, 
                clientSecret)

    if err != nil {
        return nil, errors.New(
                fmt.Sprintf("The specified secret for the custom resource, " +
                    "%s, does not exist.", cr.Spec.ClientSecret))
    }

    err = a.ValidateSecret(clientSecret)

    if err != nil {
        return nil, err
    }

    /*
     * Retrieve the endpoints for the verify tenant.
     */

    endpointUrl, err := a.GetSecretData(clientSecret, discoveryEndpointKey)

    if (err != nil) {
        return nil, err
    }

    endpoints, err := a.GetEndpoints(endpointUrl)

    if err != nil {
        return nil, err
    }

    /*
     * Retrieve the access token which is to be used in the client
     * registration.
     */

    accessToken, err := a.GetAccessToken(endpoints.TokenEndpoint, clientSecret)

    if err != nil {
        return nil, err
    }

    /*
     * Now we can perform the registration with Verify.
     */

    return a.RegisterWithVerify(cr, ingress, endpointUrl, appName, appUrl, 
                                    endpoints.RegistrationEndpoint, accessToken)
}

/*****************************************************************************/

/*
 * The RetrieveCR function is used to retrieve the custom resource which
 * is to be used for the Ingress annotation.
 */

func (a *ingressAnnotator) RetrieveCR(
                    ingress *netv1.Ingress) (*ibmv1.IBMSecurityVerify, error) {
    cr := &ibmv1.IBMSecurityVerify{}

    crName, found := ingress.Annotations[crNameKey]

    if ! found {
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

    } else {
        err := a.client.Get(context.TODO(), 
                client.ObjectKey{
                    Namespace: ingress.Namespace,
                    Name:      crName,
                }, 
                cr)

        if err != nil {
            return nil, errors.New(
                fmt.Sprintf("The verify.ibm.com/cr.name annotation, %s, does " +
                    "not correspond to an existing custom resource.", 
                    crName))
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
                    ingress   *netv1.Ingress,
                    namespace string,
                    name      string) (error) {

    /*
     * Add some new annotations.
     */

    ingress.Annotations["kubernetes.io/ingress.class"] = "nginx"
    ingress.Annotations["nginx.org/location-snippets"] = 
                                    "auth_request /verify-oidc;"
    ingress.Annotations["nginx.org/server-snippets"]   = 
                    fmt.Sprintf(nginxAnnotation, namespace, name)

    /*
     * Remove some existing annotations which are no longer required.
     */

    fields := []string {
        appNameKey,
        appUrlKey,
        crNameKey,
        consentKey,
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
                                discoveryUrl string) (*Endpoints, error) {

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

        a.log.Info("Failed to retrieve the endpoints.", 
                        "URL",    discoveryUrl,
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

    return &endpoints, nil
}

/*****************************************************************************/

/*
 * Retrieve the access token for the client.
 */

func (a *ingressAnnotator) GetAccessToken(
                                    tokenUrl string,
                                    secret   *apiv1.Secret) (string, error) {

    /*
     * Work out the client ID and secret to be used.
     */

    clientId, err := a.GetSecretData(secret, clientIdKey)

    if err != nil {
        return "", err
    }

    clientSecret, err := a.GetSecretData(secret, clientSecretKey)

    if err != nil {
        return "", err
    }

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

        a.log.Info("Failed to retrieve an access token.", 
                        "URL",    tokenUrl,
                        "status", response.StatusCode,
                        "body",   response.Body)

        return "", errors.New(
                        fmt.Sprintf("An unexpected response was received: %d", 
                        response.StatusCode))
    }

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
                            cr                *ibmv1.IBMSecurityVerify,
                            ingress           *netv1.Ingress,
                            discoveryEndpoint string,
                            appName           string,
                            appUrl            string,
                            registrationUrl   string,
                            accessToken       string) (*apiv1.Secret, error) {
    /*
     * Work out whether a consent action has been supplied.
     */

    consentAction, found := ingress.Annotations[consentKey]

    if !found {
        consentAction = defaultConsentAction
    }

    /*
     * Construct the request body.
     */

    type Request struct {
        ClientName       string   `json:"client_name"`
        RedirectUris     []string `json:"redirect_uris"`
        ConsentAction    string   `json:"consent_action"`
        AllUsersEntitled bool     `json:"all_users_entitled"`
        LoginUrl         string   `json:"initiate_login_uri"`
        EnforcePkce      bool     `json:"enforce_pkce"`
    }

    body := &Request {
        ClientName:       appName,
        RedirectUris:     []string { cr.Spec.IngressRoot + oidcAuthUri },
        ConsentAction:    consentAction,
        AllUsersEntitled: true,
        LoginUrl:         appUrl,
        EnforcePkce:      false,
    }

    payloadBuf := new(bytes.Buffer)

    json.NewEncoder(payloadBuf).Encode(body)

    /*
     * Set up the request.
     */

    request, err := http.NewRequest("POST", registrationUrl, payloadBuf)

    if err != nil {
        return nil, err
    }

    request.Header.Add("Accept", "application/json")
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
        a.log.Info("Failed to register the client.", 
                        "URL",    registrationUrl,
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

    err = a.client.Create(context.TODO(), secret)

    if err != nil {
        return nil, err
    }

    return secret, nil
}

/*****************************************************************************/

/*
 * Retrieve the base64 decoded piece of data from the supplied secret.
 */

func (a *ingressAnnotator) GetSecretData(
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

