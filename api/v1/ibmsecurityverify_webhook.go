/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package v1

/*****************************************************************************/

import (
    "context"
    "errors"
    "fmt"

    "k8s.io/apimachinery/pkg/runtime"
    "sigs.k8s.io/controller-runtime/pkg/webhook"
    "sigs.k8s.io/controller-runtime/pkg/client"

    apiV1   "k8s.io/api/core/v1"

    ctrl "sigs.k8s.io/controller-runtime"
    logf "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

/*
 * The following log object is for logging in this package.
 */

var ibmsecurityverifyLog = logf.Log.WithName("ibmsecurityverify-resource")

/*
 * The following object allows us to access the Kubernetes API.
 */

var ibmsecurityverifyClient client.Client

/*****************************************************************************/

/*
 * The following function is used to set up the Web hook with the Manager.
 */

func (r *IBMSecurityVerify) SetupWebhookWithManager(mgr ctrl.Manager) error {
    ibmsecurityverifyClient = mgr.GetClient()

    return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/validate-ibm-com-v1-ibmsecurityverify,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifies,verbs=create;update,versions=v1,name=vibmsecurityverify.kb.io,admissionReviewVersions={v1,v1beta1}

/*****************************************************************************/

var _ webhook.Validator = &IBMSecurityVerify{}

/*
 * The ValidateCreate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for create operations.
 */

func (r *IBMSecurityVerify) ValidateCreate() error {
    ibmsecurityverifyLog.Info("validate create", "name", r.Name)

    /*
     * The first thing which we need to do here is to retrieve the secret
     * which is referenced by the CR.
     */

    secret := &apiV1.Secret{}

    err := ibmsecurityverifyClient.Get(context.TODO(), 
            client.ObjectKey{
		Namespace: r.Namespace,
		Name:      r.Spec.TenantSecret,
            }, 
            secret)

    if err != nil {
        return errors.New(fmt.Sprintf("The spec.tenantSecret field, %s, does " +
                "not correspond to an available secret.", r.Spec.TenantSecret))
    }

    /*
     * Now we need to ensure that the secret contains all of the required
     * fields.
     */

    fields := []string {
        "client_id",
        "client_secret",
        "discovery_endpoint",
    }

    for _, field := range fields {
        _, ok := secret.Data[field]

        if !ok {
            return errors.New(fmt.Sprintf("The secret, %s, is missing at " +
                    "least one required field: %s", r.Spec.TenantSecret, field))
        }
    }

    return nil
}

/*****************************************************************************/

/*
 * The ValidateUpdate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for update operations.
 */

func (r *IBMSecurityVerify) ValidateUpdate(old runtime.Object) error {
    ibmsecurityverifyLog.Info("validate update", "name", r.Name)

    return errors.New("The Verify Operator does not support the update of " +
                        "IBMSecurityVerify custom resources.")
}

/*****************************************************************************/

/*
 * The ValidateDelete function implements a webhook.Validator so that a webhook
 * will be registered for the type and invoked for delete operations.  This
 * function is a no-op.
 */

func (r *IBMSecurityVerify) ValidateDelete() error {
    ibmsecurityverifyLog.Info("validate delete", "name", r.Name)

    return nil
}

/*****************************************************************************/

