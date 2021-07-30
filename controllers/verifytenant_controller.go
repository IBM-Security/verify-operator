/*
Copyright 2021 Lachlan Gleeson.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ibmv1alpha1 "github.com/IBM-Security/verify-operator/api/v1alpha1"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// VerifyTenantReconciler reconciles a VerifyTenant object
type VerifyTenantReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HttpClient HTTPClient
}

// JSON Response from Verify for tenant creation; only care about the tenant domain name and the
// extended data which contains the oauth client
type VerifyTenantOIDCClient struct {
	ClientId     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Entitlements []string `json:"entitlements"`
}
type VerifyTenantExtendedData struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type VerifyTenantJson struct {
	Id           string                     `json:"id"`
	PrimaryUrl   string                     `json:"primaryURL"`
	ExtendedData []VerifyTenantExtendedData `json:"extendedData"`
}

type VerifyOIDCGrantResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	GrantId     string `json:"grant_id"`
	IdToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

var _log = logf.Log.WithName("verify_tenant_controller")
var _verify_super_tenant_access_token = ""

const _verify_tenant_finalizer = "finalizer.verify.tenant.ibm.com"

//+kubebuilder:rbac:groups=ibm.com,resources=verifytenants,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ibm.com,resources=verifytenants/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ibm.com,resources=verifytenants/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VerifyTenant object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *VerifyTenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_log.Info("Reconcile VerifyTenant entry")

	// your logic here
	//Get our custom resource
	instance := &ibmv1alpha1.VerifyTenant{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, instance)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	tenantParams := url.Values{}
	tenantParams.Set("requestedHostname", instance.Spec.Tenant)
	tenantParams.Set("companyName", instance.Spec.Company)
	tenantParams.Set("contactEmail", instance.Spec.Contact)
	tenantParams.Set("wait", "true")
	tenantParams.Set("isTrial", "false")

	//Check if r.Status contains a version
	if instance.Status.Version > 0 { //If it does then we need to check if the secret needs to be updated
		if instance.Status.Version != instance.Spec.Version {
			_log.Info("Updating OIDC client")
			url := fmt.Sprintf("https://%s/tms/v1.0/integration/extendeddata/%s/%s", instance.Spec.SuperTenant, instance.Spec.Integration, instance.Status.TenantUUID)
			_, err := r.makeRequest(instance, url, "")
			if err != nil {
				return reconcile.Result{}, err
			}
			tenantJson, err := r.getTenantConfig(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
			oidcClient, err := r.getOIDCClientData(tenantJson)
			if err != nil {
				return reconcile.Result{}, err
			}
			if err := r.createOrUpdateSecrets(oidcClient, tenantJson, instance); err != nil {
				return reconcile.Result{}, err
			}
			instance.Status.Version = instance.Spec.Version
			if err := r.Client.Status().Update(context.TODO(), instance); err != nil {
				return reconcile.Result{}, err
			}
			_log.Info("Client secret regenerated")
		} else {
			_log.Info("Version is correct, nothing to do")
		}
	} else { //Otherwise create the Verify tenant and store the generated client id and secret
		_log.Info("Creating OIDC client")
		url := fmt.Sprintf("https://%s/tms/v1.0/integration/tenant/%s", instance.Spec.SuperTenant, instance.Spec.Integration)
		body, err := r.makeRequest(instance, url, tenantParams.Encode())
		if err != nil {
			return reconcile.Result{}, err
		}
		var tenantData VerifyTenantJson
		json.Unmarshal(body, &tenantData)
		oidcClient, err := r.getOIDCClientData(&tenantData)
		if err != nil {
			return reconcile.Result{}, err
		}
		if tenantData.Id == "" {
			return reconcile.Result{}, errors.New("Tenant Id not found in HTTP response")
		}
		instance.Status.TenantUUID = tenantData.Id
		err = r.createOrUpdateSecrets(oidcClient, &tenantData, instance)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Version = instance.Spec.Version
		if err := r.Client.Status().Update(context.TODO(), instance); err != nil {
			return reconcile.Result{}, err
		}
		_log.Info("Client secret created")
	}

	// Check if verify tenant is scheduled for deletion
	if !instance.GetDeletionTimestamp().IsZero() {
		_log.Info("Checking finalizer")
		if instance.HasFinalizer(_verify_tenant_finalizer) {
			_log.Info("Running VerifyTenant Finalizer")
			if err := r.cleanupSecrets(instance); err != nil {
				return ctrl.Result{}, err
			}
			instance.RemoveFinalizer(_verify_tenant_finalizer)
			if err := r.Update(context.TODO(), instance); err != nil {
				return ctrl.Result{}, err
			} // If we are scheduled for deletion return at this point or the finalizer will be readded
			_log.Info("Completed VerifyTenant Finalizer")
		}
	} else if !instance.HasFinalizer(_verify_tenant_finalizer) {
		// Add the finalizer if required
		instance.AddFinalizer(_verify_tenant_finalizer)
		if err := r.Update(context.TODO(), instance); err != nil {
			return ctrl.Result{}, err
		}
	}
	_log.Info("Reconcile VerifyTenant exit")
	return ctrl.Result{}, nil
}

func (r *VerifyTenantReconciler) makeRequest(cr *ibmv1alpha1.VerifyTenant, url string, queryParams string) ([]byte, error) {
	jsonParams := []byte(`[{"key":"oauthClient",
			"value": "{\"entitlements\":[\"manageOidcGrants\",\"manageApiClients\",\"manageUsers\"]}"}]`)
	request, err := http.NewRequest("POST", url, ioutil.NopCloser(bytes.NewBuffer(jsonParams)))
	if err != nil {
		return nil, err
	}
	if queryParams != "" {
		request.URL.RawQuery = queryParams
	}
	request.Header.Add("Content-Type", "application/json; charset=UTF-8")
	request.Header.Add("Accept", "application/json")
	access_token, err := r.getAccessToken(cr)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", access_token))
	response, err := r.HttpClient.Do(request)
	if err != nil {
		return nil, err
	} else if response.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Failed to create a new tenant with name \"%s\"", cr.Spec.Tenant))
	} else {
		body, _ := ioutil.ReadAll(response.Body)
		return body, nil
	}
}

func (r *VerifyTenantReconciler) getAccessToken(cr *ibmv1alpha1.VerifyTenant) (string, error) {
	if time.Now().Unix() < cr.Status.AccessTokenExpiry-30 {
		//If the access token is not going to expire in the next 30 seconds reuse it
		_log.Info("In memory access token still valid, reusing it")
		return _verify_super_tenant_access_token, nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", cr.Spec.ClientId)
	data.Set("client_secret", cr.Spec.ClientSecret)
	data.Set("scope", "openid")

	client := &http.Client{}
	request, err := http.NewRequest("POST", fmt.Sprintf("https://%s/v1.0/endpoint/default/token", cr.Spec.SuperTenant),
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	response, err := client.Do(request)
	if err != nil {
		_log.Info("Error getting access token")
		return "", err
	}

	var jsonData VerifyOIDCGrantResponse
	json.NewDecoder(response.Body).Decode(&jsonData)

	// Set expiry in status to minimise access token generation
	cr.Status.AccessTokenExpiry = time.Now().Unix() + int64(jsonData.ExpiresIn)
	_verify_super_tenant_access_token = jsonData.AccessToken

	return jsonData.AccessToken, nil
}

func (r *VerifyTenantReconciler) getTenantConfig(cr *ibmv1alpha1.VerifyTenant) (*VerifyTenantJson, error) {
	uri := fmt.Sprintf("https://%s/tms/v1.0/integration/tenants/%s", cr.Spec.SuperTenant, cr.Spec.Integration)
	request, err := http.NewRequest("GET", uri, nil)
	tenantParams := url.Values{}
	tenantParams.Set("tenantId", cr.Status.TenantUUID)
	request.URL.RawQuery = tenantParams.Encode()
	request.Header.Add("Content-Type", "application/json; charset=UTF-8")
	request.Header.Add("Accept", "application/json")
	access_token, err := r.getAccessToken(cr)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", access_token))
	client := &http.Client{}
	response, err := client.Do(request)
	tenantJson := make([]VerifyTenantJson, 0)
	json.NewDecoder(response.Body).Decode(&tenantJson)
	if len(tenantJson) != 1 {
		return nil, errors.New(fmt.Sprintf("Got multiple tenants for tenant uuid %s", cr.Status.TenantUUID))
	}
	return &tenantJson[0], nil
}

func (r *VerifyTenantReconciler) getOIDCClientData(tenant *VerifyTenantJson) (*VerifyTenantOIDCClient, error) {
	//Find the client id and client secret in the extended data
	var oidcClient VerifyTenantOIDCClient
	var err error
	for i := 0; i < len(tenant.ExtendedData); i++ {
		if tenant.ExtendedData[i].Key == "oauthClient" {
			err = json.Unmarshal([]byte(tenant.ExtendedData[i].Value), &oidcClient)
			break
		}
	}
	return &oidcClient, err
}

func (r *VerifyTenantReconciler) createOrUpdateSecrets(oidcClient *VerifyTenantOIDCClient, tenantJson *VerifyTenantJson, cr *ibmv1alpha1.VerifyTenant) error {
	//TODO
	//Check the cr.Status.Namespaces; if any have been removed make sure the secret is removed
	for _, secretNamespace := range cr.Status.WatchedNamespaces {
		found := false
		for _, ele := range cr.Spec.Namespaces {
			if ele == secretNamespace {
				found = true
				break
			}
		}
		if !found { //If not found in new list, GC it
			expiredSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: secretNamespace,
					Name:      cr.Spec.Secret,
				},
			}
			// Not much we can do if it can't be deleted
			_ = r.Client.Delete(context.TODO(), expiredSecret)
		}
	}

	for _, secretNamespace := range cr.Spec.Namespaces {
		// Get the Secret
		foundSecret := &corev1.Secret{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Spec.Secret, Namespace: secretNamespace}, foundSecret)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				//Create it
				if err := r.createSecret(tenantJson, oidcClient, secretNamespace, cr); err != nil {
					return err
				}
				continue
			} else {
				return err
			}
		}
		//Exists so update it
		if err = r.updateSecret(tenantJson, oidcClient, foundSecret); err != nil {
			return err
		}
	}
	// At this point the spec and status should be the same list
	cr.Status.WatchedNamespaces = cr.Spec.Namespaces
	return nil
}

func (r *VerifyTenantReconciler) updateSecret(tenantJson *VerifyTenantJson, oidcClient *VerifyTenantOIDCClient,
	foundSecret *corev1.Secret) error {
	var err error
	newData := map[string]string{
		"tenant":        tenantJson.PrimaryUrl,
		"client_id":     oidcClient.ClientId,
		"client_secret": oidcClient.ClientSecret,
	}
	if !reflect.DeepEqual(newData, foundSecret.StringData) {
		foundSecret.StringData = newData
		err = r.Client.Update(context.TODO(), foundSecret)
	}
	return err
}

func (r *VerifyTenantReconciler) createSecret(tenantJson *VerifyTenantJson, oidcClient *VerifyTenantOIDCClient,
	namespace string, cr *ibmv1alpha1.VerifyTenant) error {
	labels := map[string]string{
		"app": cr.Name,
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Secret,
			Namespace: namespace,
			Labels:    labels,
		},
		Type: "generic",
		StringData: map[string]string{
			"tenant":        tenantJson.PrimaryUrl,
			"client_id":     oidcClient.ClientId,
			"client_secret": oidcClient.ClientSecret,
		},
	}
	return r.Client.Create(context.TODO(), &secret)
}

func (r *VerifyTenantReconciler) cleanupSecrets(cr *ibmv1alpha1.VerifyTenant) error {
	for _, secretNamespace := range cr.Status.WatchedNamespaces {
		expiredSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: secretNamespace,
				Name:      cr.Spec.Secret,
			},
		}
		// Not much we can do if it can't be deleted
		r.Client.Delete(context.TODO(), expiredSecret)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VerifyTenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ibmv1alpha1.VerifyTenant{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
