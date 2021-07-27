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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VerifyTenantSpec defines the desired state of VerifyTenant
type VerifyTenantSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// The Super Tenant which will be used to create your new IBM Verify Tenant. This shuld only include the domain
	// of the Super Tenant.
	SuperTenant string `json:"supertenant"`

	// Tenant is the prefix of the IBM Verify tenant domain which will be created. This must be an alphanumeric string.
	Tenant string `json:"tenant"`

	// The comany contact for the created tenant
	// +kubebuilder:validation:Type:="string"
	Company string `json:"company_name"`

	// The contact email address for the created tenant. This will be used for service updates and outages.
	// +kubebuilder:validation:Type:="string"
	Contact string `json:"contact_email"`

	// The version of the generated OIDC client. This is the only parameter which can be edited once deployed. When
	// incremented the operator will regenerate the client secret and update the Kubernetes Secret specified by
	// "target_secret".
	// +kubebuilder:default:=1
	Version int `json:"oidc_client_version"`

	// The name of the secret to be created.
	// +kubebuilder:default:="verify-tenant"
	Secret string `json:"target_secret"`

	// The integration type to use. Default is CP4S
	// +kubeuilder:default:="CP4S"
	Integration string `json:"integration"`

	// The OIDC client id with permission to provision new Tenants from the Super Tenant
	ClientId string `json:"client_id"`

	// The OIDC client secret associated with the client id
	ClientSecret string `json:"client_secret"`
}

// VerifyTenantStatus defines the observed state of VerifyTenant
type VerifyTenantStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Tennant UUID is recorded in the status to allow for the rollover of client_secret when requested
	TenantUUID string `json:"tennant_uuid,omitempty"`

	// Version of client secret deployed
	// +kubebuilder:default:=0
	Version int `json:"version"`

	// Length of time that current access token is valid for
	AccessTokenExpiry int64 `json:"access_token_expiry"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VerifyTenant is the Schema for the verifytenants API
type VerifyTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VerifyTenantSpec   `json:"spec,omitempty"`
	Status VerifyTenantStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VerifyTenantList contains a list of VerifyTenant
type VerifyTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VerifyTenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VerifyTenant{}, &VerifyTenantList{})
}
