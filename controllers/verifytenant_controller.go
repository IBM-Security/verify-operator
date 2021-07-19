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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ibmv1alpha1 "github.com/IBM-Security/verify-operator/api/v1alpha1"
)

// VerifyTenantReconciler reconciles a VerifyTenant object
type VerifyTenantReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// JSON Response from Verify for tenant creation
type VerifyCreateResponse struct {
	tenant        string
	client_id     string
	client_secret string
}

type VerifyOIDCGrantResponse struct {
	access_token string
	scope        string
	grant_id     string
	id_token     string
	token_type   string
	expires_in   int
}

var _log = logf.Log.WithName("verify_tenant_controller")

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
		if errors.IsNotFound(err) {
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
			//Client secret needs to be updated
			jsonParams, err := r.regenerateSecretJson(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
			url := fmt.Sprintf("https://%s/tms/v1.0/integration/extendeddata/%s/%s", cr.Spec.SuperTenant, cr.Spec.Integration, cr.Spec.TennantUUID)
			response, err := r.makeRequest(instance, url, tenantParams.Encode(), jsonParams)
			if err != nil {
				return reconcile.Result{}, err
			}
			err = r.updateSecret(*response, instance)
			if err != nil {
				return reconcile.Result{}, err
			}
			_log.Info("Client secret regenrated")

		} else {
			_log.Info("Version is correct, nothing to do")
		}
	} else { //Otherwise create the Verify tenant and store the generated client id and secret
		jsonParams := []byte(`[{"key":"oauthClient",
				"value": "{\"entitlements\":[\"manageOidcGrants\",\"manageApiClients\",\"manageUsers\"]}"}]`)
		url := fmt.Sprintf("https://%s/tms/v1.0/integration/tenant/%s", cr.Spec.SuperTenant, cr.Spec.Integration)
		response, err := r.makeRequest(instance, url, "POST", tenantParams.Encode(), jsonParams)
		if err != nil {
			return reconcile.Result{}, err
		}
		secret := r.createSecret(*response, instance)
		err = r.Client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}
	}
	_log.Info("Reconcile VerifyTenant exit")
	return ctrl.Result{}, nil
}

func (r *VerifyTenantReconciler) regenerateSecretJson(cr *ibmv1alpha1.VerifyTenant) ([]byte, error) {

	tenantSecret := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace},
		tenantSecret)
	if err != nil {
		return nil, err
	}
	if err := controllerutil.SetControllerReference(cr, tenantSecret, r.Scheme); err != nil {
		return nil, err
	}

	// Read client id
	clientId := string(tenantSecret.Data["client_id"])
	if clientId == "" {
		return nil, errors.NewNotFound(corev1.Resource("secret"), "Client id not found")
	}
	//Can now create the JSON to regenerate the client secret
	jsonData := []byte(`[{"key": "oauthClient", "value": "{\"clientId\":\"` + clientId + `\",\"entitlements\":
				[\"manageOidcGrants\",\"manageApiClients\",\"manageUsers\"]}"}]`)
	return jsonData, nil
}

func (r *VerifyTenantReconciler) makeRequest(cr *ibmv1alpha1.VerifyTenant, url string, queryParams string,
	jsonParams []byte) (*http.Response, error) {
	request, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	if queryParams != "" {
		request.URL.RawQuery = queryParams
	}
	if jsonParams != nil {
		request.Body = ioutil.NopCloser(bytes.NewBuffer(jsonParams))
	}
	request.Header.Add("Content-Type", "application/json; charset=UTF-8")
	request.Header.Add("Accept", "application/json")
	access_token, err := r.getAccessToken(cr)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer: %s", access_token))
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	} else {
		defer response.Body.Close()
		return response, nil
	}
}

func (r *VerifyTenantReconciler) getAccessToken(cr *ibmv1alpha1.VerifyTenant) (string, error) {
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
		return "", err
	}
	jsonData := &VerifyOIDCGrantResponse{}
	json.NewDecoder(response.Body).Decode(&jsonData)

	//TODO set expiry in status to minimise access token generation

	return jsonData.access_token, nil
}

func (r *VerifyTenantReconciler) createSecret(response http.Response, cr *ibmv1alpha1.VerifyTenant) *corev1.Secret {
	labels := map[string]string{
		"app": cr.Name,
	}
	jsonData := &VerifyCreateResponse{}
	json.NewDecoder(response.Body).Decode(&jsonData)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-secret",
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Type: "generic",
		StringData: map[string]string{
			"tenant":        jsonData.tenant,
			"client_id":     jsonData.client_id,
			"client_secret": jsonData.client_secret,
		},
	}
}

func (r *VerifyTenantReconciler) updateSecret(response http.Response, cr *ibmv1alpha1.VerifyTenant) error {
	//TODO
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
