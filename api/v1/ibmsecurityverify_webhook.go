/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package v1

/*****************************************************************************/

import (
    "errors"

    "k8s.io/apimachinery/pkg/runtime"
    "sigs.k8s.io/controller-runtime/pkg/webhook"

    ctrl "sigs.k8s.io/controller-runtime"
    logf "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

/*
 * The following log object is for logging in this package.
 */

var ibmsecurityverifylog = logf.Log.WithName("ibmsecurityverify-resource")

/*****************************************************************************/

/*
 * The following function is used to set up the Web hook with the Manager.
 */

func (r *IBMSecurityVerify) SetupWebhookWithManager(mgr ctrl.Manager) error {
    return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/mutate-ibm-com-v1-ibmsecurityverify,mutating=true,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifies,verbs=create;update,versions=v1,name=mibmsecurityverify.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &IBMSecurityVerify{}

/*
 * The Default function implements a webhook.Defaulter so that a webhook will 
 * be registered for the type.
 */

func (r *IBMSecurityVerify) Default() {
    ibmsecurityverifylog.Info("default", "name", r.Name)
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/validate-ibm-com-v1-ibmsecurityverify,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifies,verbs=create;update,versions=v1,name=vibmsecurityverify.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &IBMSecurityVerify{}

/*
 * The ValidateCreate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for create operations.
 */

func (r *IBMSecurityVerify) ValidateCreate() error {
    ibmsecurityverifylog.Info("validate create", "name", r.Name)
    ibmsecurityverifylog.Info("validate create", "spec.foo", r.Spec.Foo)

    if r.Spec.Foo == "invalid" {
        return errors.New("An invalid value was specified for Spec.Foo")
    }

    return nil
}

/*****************************************************************************/

/*
 * The ValidateUpdate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for update operations.
 */

func (r *IBMSecurityVerify) ValidateUpdate(old runtime.Object) error {
    ibmsecurityverifylog.Info("validate update", "name", r.Name)

    return nil
}

/*****************************************************************************/

/*
 * The ValidateDelete function implements a webhook.Validator so that a webhook  * will be registered for the type and invoked for delete operations.
 */

func (r *IBMSecurityVerify) ValidateDelete() error {
    ibmsecurityverifylog.Info("validate delete", "name", r.Name)

    return nil
}

/*****************************************************************************/

