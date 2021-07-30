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
	"net"
	"net/mail"
	"strconv"
	"strings"
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
//+kubebuilder:webhook:path=/validate-ibm-com-v1alpha1-verifytenant,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=verifytenants,verbs=create;update,versions=v1alpha1,name=vverifytenant.kb.io,admissionReviewVersions={v1alpha1,v1beta1}

var _ webhook.Validator = &VerifyTenant{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateCreate() error {
	_verifytenantlog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	err := r.validateSuperTenant(r.Spec.SuperTenant)
	if err != nil {
		return err
	}
	err = r.validateTenantPrefix(r.Spec.Tenant)
	if err != nil {
		return err
	}
	err = r.validateEmail(r.Spec.Contact)
	if err != nil {
		return err
	}
	err = r.validateNamespaces(r.Spec.Namespaces)
	if err != nil {
		return err
	}
	if r.Spec.Version < 1 {
		return errors.New(fmt.Sprintf("Invalid version: %d, must be >= 0", r.Spec.Version))
	}
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateUpdate(old runtime.Object) error {
	_verifytenantlog.Info("validate update", "name", r.Name)
	oldCr := old.(*VerifyTenant)

	// Validated on create so just make sure they have not changed
	if r.Spec.SuperTenant != oldCr.Spec.SuperTenant {
		return errors.New("Editing the SuperTenant attribute is not allowed")
	}
	if r.Spec.Tenant != oldCr.Spec.Tenant {
		return errors.New("Editing the Tenant attribute is not allowed")
	}
	if r.Spec.Company != oldCr.Spec.Company {
		return errors.New("Editing the Company attribute is not allowed")
	}
	if r.Spec.Contact != oldCr.Spec.Contact {
		return errors.New("Editing the Contact attribute is not allowed")
	}
	if r.Spec.Secret != oldCr.Spec.Secret {
		return errors.New("Editing the Secret attribute is not allowed")
	}
	if r.Spec.Integration != oldCr.Spec.Integration {
		return errors.New("Editing the Integration attribute is not allowed")
	}
	// Cannot decrement the version
	if r.Spec.Version < 1 || r.Spec.Version < r.Status.Version {
		return errors.New(fmt.Sprintf("Invalid version: %d, version must be incremented", r.Spec.Version))
	}
	if err := r.validateNamespaces(r.Spec.Namespaces); err != nil {
		return err
	}
	changed, err := r.targetNamespacesChanged(r.Spec.Namespaces, r.Status.WatchedNamespaces)
	if err != nil {
		return err
	}
	if changed { //If the list of namespaces has changed we have to enforce that the version is incremented
		if r.Spec.Version == r.Status.Version {
			return errors.New("Change in target namespaces detected, the OIDC client version must also be incremented")
		}
	}
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *VerifyTenant) ValidateDelete() error {
	_verifytenantlog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}

func (r *VerifyTenant) validateSuperTenant(superTenant string) error {
	//If ip address is specified check its valid
	parts := strings.SplitN(superTenant, ":", 2)
	domain := parts[0]
	if len(parts) == 2 {
		port := parts[1]
		if _, err := strconv.Atoi(port); err != nil {
			return errors.New(fmt.Sprintf("Invalid port specified %s", port))
		}
	}
	if domain[0] >= '0' && domain[0] <= '9' {
		//Must be ip adress
		if net.ParseIP(domain) == nil {
			return errors.New(fmt.Sprintf("Invalid IP address %s", domain))
		}
	} else {
		//Must be a domain; use relaxed rules here and only check for invalid characters
		for i := 0; i < len(domain); i++ {
			char := domain[i]
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.' || char >= 'A' && char <= 'Z') {
				return errors.New(fmt.Sprintf("Invalid character %c in hostname: %v", char, domain))
			}
		}
	}
	return nil
}

func (r *VerifyTenant) validateTenantPrefix(tenant string) error {
	//Cannot start with a digit
	if tenant[0] <= '0' && tenant[0] >= '9' {
		return errors.New(fmt.Sprintf("Invalid tenant name specified: %s", tenant))
	}

	//Check for invalid characters; Verify doc says must match regular expression "^[a-z0-9]+(-[a-z0-9]+)*$"
	strlen := len(tenant) - 1
	for i := 0; i < len(tenant); i++ {
		char := tenant[i]
		if (i == 0 || i == strlen) &&
			!(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char >= 'A' && char <= 'Z') {
			//First and last character must be alphanumeric
			return errors.New(fmt.Sprintf("Invalid char %c at offset %d in requested tenant name %s", char, i,
				tenant))
		} else if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char >= 'A' && char <= 'Z') {
			//Otherwise must be alphanumeric or '-'
			return errors.New(fmt.Sprintf("Invalid char %c in requested tenant name %s", char, tenant))
		}
	}
	return nil
}

func (r *VerifyTenant) validateEmail(address string) error {
	_, err := mail.ParseAddress(address)
	return err
}

func (r *VerifyTenant) validateNamespaces(namespaces []string) error {
	if namespaces == nil {
		return errors.New("Must specify at least one namespace")
	}
	for _, namespace := range namespaces {
		for _, char := range namespace {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char >= 'A' && char <= 'Z') {
				return errors.New(fmt.Sprintf("Character %c in namespace %s is invalid", char, namespace))
			}
		}
	}
	return nil
}

func (r *VerifyTenant) targetNamespacesChanged(newNamespaces []string, currentNamespaces []string) (bool, error) {
	same := true
	if len(newNamespaces) < 1 {
		return same, errors.New("Must specify at least one namespace")
	} else if len(newNamespaces) != len(currentNamespaces) {
		// If they are different lengths they must be different
		same = false
	} else {
		for _, name := range newNamespaces {
			found := false
			for _, ele := range currentNamespaces {
				if ele == name { //Try to find name in currentNamespaces
					found = true
					break
				}
			}
			if !found { // If not found
				same = false
				break
			}
		}
	}
	return same, nil
}
