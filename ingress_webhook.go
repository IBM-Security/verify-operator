/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"

    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

    ibmv1 "github.com/ibm-security/verify-operator/api/v1"
    apiV1 "k8s.io/api/core/v1"
    netv1 "k8s.io/api/networking/v1"
    logf  "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

// +kubebuilder:webhook:path=/mutate-v1-ingress,mutating=true,failurePolicy=fail,sideEffects=None,groups=networking.k8s.io,resources=ingresses,verbs=create;update,versions=v1,name=mingress.kb.io,admissionReviewVersions={v1,v1beta1}

/*****************************************************************************/

/*
 * Our annotator structure.
 */

type ingressAnnotator struct {
    client  client.Client
    decoder *admission.Decoder
}

/*****************************************************************************/

/*
 * A logger which can be used with this webhook object.
 */

var mylog = logf.Log.WithName("ingress-resource")

/*****************************************************************************/

/*
 * The Handle() function is called whenever the ingress is created and is used
 * to add the correct annotations to the ingress.
 */

func (a *ingressAnnotator) Handle(
            ctx context.Context, req admission.Request) admission.Response {
    /*
     * Grab the ingress information.
     */

    ingress := &netv1.Ingress{}

    err := a.decoder.Decode(req, ingress)

    if err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }

    mylog.Info("Handle", "name", ingress.Name)

    /*
     * Early exit if there are no annotations present.
     */

    if ingress.Annotations == nil {
        return admission.Allowed("No annotations present.")
    }

    /*
     * Check see see whether we have been told to protect this Ingress
     * resource.  This is controlled by the presence of the
     * verify.ibm.com/cr.name annotation.
     */

    crName, found := ingress.Annotations["verify.ibm.com/cr.name"]

    if !found {
        return admission.Allowed(
                    "No verify.ibm.com/cr.name annotation present.")
    }

    /*
     * Verify that the custom resource actually exists.
     */

    cr := &ibmv1.IBMSecurityVerify{}

    err = a.client.Get(context.TODO(), 
            client.ObjectKey{
		Namespace: ingress.Namespace,
		Name:      crName,
            }, 
            cr)

    if err != nil {
        return admission.Errored(http.StatusBadRequest, errors.New(
            fmt.Sprintf("The verify.ibm.com/cr.name annotation, %s, does " +
                "not correspond to an existing custom resource.", 
                crName)))
    }

    /*
     * Construct the name of the secret which will contain the credential
     * information for the application.
     */

    secretName := fmt.Sprintf("verify-app-%s", ingress.Name)

    /*
     * Retrieve the secret which contains the credentials for the application.
     */

    secret := &apiV1.Secret{}

    err = a.client.Get(context.TODO(), 
            client.ObjectKey{
		Namespace: ingress.Namespace,
		Name:      secretName,
            }, 
            secret)

    if err != nil {
        secret, err = a.RegisterApplication(ingress.Annotations, cr)

        if err != nil {
            return admission.Errored(http.StatusBadRequest, err)
        }
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
            return admission.Errored(http.StatusBadRequest, errors.New(
                fmt.Sprintf("The secret, %s, is missing at " +
                    "least one required field: %s", secretName, field)))
        }
    }

    /*
     * Add the annotation to the ingress.
     */

    ingress.Annotations["example-mutating-admission-webhook"] = "foo"

    /*
     * Marshal and return the updated ingress definition.
     */

    marshaledIngress, err := json.Marshal(ingress)

    if err != nil {
        return admission.Errored(http.StatusInternalServerError, err)
    }

    return admission.PatchResponseFromRaw(req.Object.Raw, marshaledIngress)
}

/*****************************************************************************/

/*
 * The registerApplication function is used to register the new application
 * with IBM Security Verify.
 */

func (a *ingressAnnotator) RegisterApplication(
                annotations map[string]string, 
                cr          *ibmv1.IBMSecurityVerify) (*apiV1.Secret, error) {
    return &apiV1.Secret{}, errors.New(
            "XXX: still to be done: dynamic client registration")
}

/*****************************************************************************/

/*
 * The InjectDecoder function injects the decoder.
 */

func (a *ingressAnnotator) InjectDecoder(d *admission.Decoder) error {
    a.decoder = d

    return nil
}

/*****************************************************************************/

