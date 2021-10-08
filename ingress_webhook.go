/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

import (
    "context"
    "encoding/json"
    "net/http"

    netv1 "k8s.io/api/networking/v1"

    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

    logf "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

// +kubebuilder:webhook:path=/mutate-v1-ingress,mutating=true,failurePolicy=fail,sideEffects=None,groups=networking.k8s.io,resources=ingresses,verbs=create;update,versions=v1,name=mingress.kb.io,admissionReviewVersions={v1,v1beta1}

/*****************************************************************************/

/*
 * Our annotator structure.
 */

type ingressAnnotator struct {
    Client  client.Client
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
    mylog.Info("Handle", "name", "XXX")

    /*
     * Grab the ingress information.
     */

    ingress := &netv1.Ingress{}

    err := a.decoder.Decode(req, ingress)

    if err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }

    /*
     * Add the annotation to the ingress.
     */

    if ingress.Annotations == nil {
        ingress.Annotations = map[string]string{}
    }

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
 * The InjectDecoder function injects the decoder.
 */

func (a *ingressAnnotator) InjectDecoder(d *admission.Decoder) error {
    a.decoder = d

    return nil
}

/*****************************************************************************/

