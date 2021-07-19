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

	// The Super Tenant which will be used to create your new IBM Verify Tenant
	SuperTenant string `json:"supertenant"`

	// Tenant is the protocol + domain for the Verify supertenant where your tenant will be created
	Tenant string `json:"tenant"`

	// The comany contact for the newly created tenant
	Company string `json:"company_name"`

	// The contact email address for the newly created tenant. This will be used for service updates and outages.
	Contact string `json:"contact_email"`

	// The version of the generated OIDC client. This is the only parameter which can be edited once deployed. When
	// incremented the operator will regenrate the client secret and update the Kubernetes Secret.
	// +kubebuilder:default:=0
	Version int `json:"version"`

	// The name of the secret to be created. Defaults to verify-tenant bu is user modifiable.
	// +kubebuilder:default:="verify-tenant"
	Secret string `json:"target_secret"`

	// The integration type to use. Default is CP4s
	// +kubeuilder:default:="CP4S"
	Integration string `json:"integration"`

	// The OIDC client id with permission to provision new Tenants from the Super Tenatn
	ClientId string `json:"client_id"`

	// The OIDC client secrent associated with the client id
	ClientSecret string `json:"client_secret"`
}

// VerifyTenantStatus defines the observed state of VerifyTenant
type VerifyTenantStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Tennant UUID is recorded in the status to allow for the rollover of client_secret when requested
	TenantUUID string `json:"tennant_uuid,omitempty"`

	// Version of client secret deployed
	Version int `json:"version,omitempty"`

	// Length of time that current access token is valid for
	AccessTokenExpiry int64 `json:"access_token_expiry,omitempty"`
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
