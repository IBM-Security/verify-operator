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

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"errors"
	"fmt"
	"net/mail"
	"net/url"
)

// log is for logging in this package.
var _verifytenantlog = logf.Log.WithName("verifytenant-resource")

func (r *VerifyTenant) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-ibm-com-v1alpha1-verifytenant,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=verifytenants,verbs=create;update,versions=v1alpha1,name=vverifytenant.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &VerifyTenant{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateCreate() error {
	_verifytenantlog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	err := r.validateDomain(r.Spec.SuperTenant)
	if err != nil {
		return err
	}
	err = r.validateDomain(r.Spec.Tenant)
	if err != nil {
		return err
	}
	err = r.validateDomain(r.Spec.Contact)
	if err != nil {
		return err
	}
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateUpdate(old runtime.Object) error {
	_verifytenantlog.Info("validate update", "name", r.Name)

	//_verifytenantlog.Info(fmt.Sprintf("unmarshalled data: %s", string(old)))
	//_verifytenantlog.Info(fmt.Sprintf("unmarshalled data: %s", string(old.UnstructuredContent())))

	// TODO(user): fill in your validation logic upon object update.
	err := r.validateDomain(r.Spec.SuperTenant)
	if err != nil {
		return err
	}
	err = r.validateDomain(r.Spec.Tenant)
	if err != nil {
		return err
	}
	err = r.validateDomain(r.Spec.Contact)
	if err != nil {
		return err
	}
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateDelete() error {
	_verifytenantlog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}

//Validate that string represents a valid domain name
func (r *VerifyTenant) validateDomain(domain string) error {

	u, err := url.ParseRequestURI(domain)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New(fmt.Sprintf("Invalid hostname specified: %v", domain))
	}
	return nil
}

func (r *VerifyTenant) validateEmail(address string) error {
	_, err := mail.ParseAddress(address)
	return err
}
