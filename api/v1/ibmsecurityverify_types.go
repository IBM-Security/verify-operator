/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package v1

/*****************************************************************************/

import (
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*****************************************************************************/

// IBMSecurityVerifySpec defines the desired state of IBMSecurityVerify.
type IBMSecurityVerifySpec struct {
    // The name of the secret which contains the IBM Security Verify
    // client credentials.
    ClientSecret string `json:"clientSecret"`

    //+kubebuilder:validation:Minimum=0
    //+kubebuilder:default=3600
    // The lifetime, in seconds, for an authenticated session.  
    // +optional
    SessionLifetime int `json:"sessionLifetime"`

    //+kubebuilder:default=/verify-sso
    // The URL path, within the Ingress service, for the Verify SSO server.
    // +optional
    AuthPath string `json:"authPath"`

    // The URL to which a client will be redirected upon logout.    If no
    // logout redirect URL is specified the server will not provide a mechanism
    // to logout the user.  The logout URI is constructed by appending the
    // '/logout' URL segment to the configured 'AuthPath'.
    // +optional
    LogoutRedirectURL string `json:"logoutRedirectURL"`
}

/*****************************************************************************/

// IBMSecurityVerifyStatus defines the observed state of IBMSecurityVerify.
type IBMSecurityVerifyStatus struct {
    // Conditions is the list of status conditions for this resource
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

/*****************************************************************************/

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IBMSecurityVerify is the Schema for the ibmsecurityverifies API.
type IBMSecurityVerify struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   IBMSecurityVerifySpec   `json:"spec,omitempty"`
    Status IBMSecurityVerifyStatus `json:"status,omitempty"`
}

/*****************************************************************************/

//+kubebuilder:object:root=true

// IBMSecurityVerifyList contains a list of IBMSecurityVerify resources.
type IBMSecurityVerifyList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []IBMSecurityVerify `json:"items"`
}

/*****************************************************************************/

func init() {
    SchemeBuilder.Register(&IBMSecurityVerify{}, &IBMSecurityVerifyList{})
}

/*****************************************************************************/

