/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package controllers

/*****************************************************************************/

import (
    "context"
    "fmt"
    "time"

    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/api/errors"

    ctrl "sigs.k8s.io/controller-runtime"

    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/log"

    "github.com/go-logr/logr"

    ibmv1  "github.com/ibm-security/verify-operator/api/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*****************************************************************************/

/*
 * The IBMSecurityVerifyReconciler structure reconciles an IBMSecurityVerify 
 * object.
 */

type IBMSecurityVerifyReconciler struct {
    client.Client

    Log    logr.Logger
    Scheme *runtime.Scheme
}

/*****************************************************************************/

//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifies/finalizers,verbs=update

/*****************************************************************************/

/*
 * Reconcile is part of the main kubernetes reconciliation loop which aims to
 * move the current state of the cluster closer to the desired state.
 *
 * For more details, check Reconcile and its Result here:
 * - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.9.2/pkg/reconcile
 */

func (r *IBMSecurityVerifyReconciler) Reconcile(
                ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

    _ = log.FromContext(ctx)

    r.Log.Info("Entering a function", "Function", "Reconcile")

    /*
     * Fetch the definition document.
     */

    verify := &ibmv1.IBMSecurityVerify{}
    err    := r.Get(ctx, req.NamespacedName, verify)

    if err != nil {
        if errors.IsNotFound(err) {
            /*
             * The requested object was not found.  It could have been deleted 
             * after the reconcile request.  
             */

            err = nil
        } else {
            /*
             * There was an error reading the object - requeue the request.
             */

            r.Log.Error(err, "Failed to get the Verify resource")
        }

        return ctrl.Result{}, err
    }

    /*
     * Add the condition to indicate that the resource has been created or
     * updated.
     */

    message := fmt.Sprintf("Configuration for %s/%s was added or updated",
                                verify.Namespace, verify.Name)

    verify.Status.Conditions = []metav1.Condition{{
        Type:               "Available",
        Status:             metav1.ConditionTrue,
        Reason:             "AddedOrUpdated",
        Message:            message,
        LastTransitionTime: metav1.NewTime(time.Now()),
    }}

    if err := r.Status().Update(ctx, verify); err != nil {
        r.Log.Error(err, "Failed to update the condition for the resource",
                                "Deployment.Namespace", verify.Namespace,
                                "Deployment.Name", verify.Name)

        return ctrl.Result{}, err
    }

    return ctrl.Result{}, nil
}

/*****************************************************************************/

/*
 * The following function is used to set up the controller with the Manager.
 */

func (r *IBMSecurityVerifyReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
            For(&ibmv1.IBMSecurityVerify{}).
            Complete(r)
}

/*****************************************************************************/

