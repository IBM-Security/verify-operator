# High Level Design

## Introduction

This document contains a high level design for the Verify Operator.  It will roughly explain how the operator works and the technologies involved.

The operator itself is implemented in the Go programming language.  The 'shell' of the operator has been created by the operator SDK.

At a high level:

1. The operator controller is responsible for managing the IBMSecurityVerify custom resource.
2. The ingress webhook is responsible for:
	1. Validating that the Verify secret specified in the IBMSecurityVerify custom resource is valid.
	2. Augmenting the 'Ingress' definitions with the required annotations to configure the Nginx Ingress controller for OIDC authentication.
3. The OIDC server is responsible for managing the OIDC RP authentication process.

![Operator Design](images/OperatorDesign.png)

## Operator Controller

The operator controller is essentially a no-op.  It defines the custom resource, but doesn't really do anything with the custom resource.

A custom resource will look like the following:

```yaml
apiVersion: ibm.com/v1
kind: IBMSecurityVerify

metadata:
  name: test-tenant.verify.ibm.com
  namespace: operators

spec:
  # The name of the secret which contains the IBM Security Verify
  # client credentials.
  clientSecret: ibm-security-verify-client-1cbfe647-9e5f-4d99-8e05-8ec1c862eb47

  # The root URL of the Nginx Ingress controller.
  ingressRoot: https://my-nginx-ingress.apps.acme.ibm.com
```

## Ingress Webhook

The Webhook is responsible for:

1. Watching for IBMSecurityVerify custom resource requests.  When a new custom resource is created the operator will validate that the specified `clientSecret` field corresponds to a known secret, and that the secret contains the required fields.  The required fields include: `client_name`, `client_id`, `client_secret`, `discovery_endpoint`.
2. Intercept the creation of Ingress definitions, and if the `verify.ibm.com/app.name` annotation is present it will:
	1. Check to see if the application has been registered with Verify, searching for a secret which has the 'product' label set to 'ibm-security-verify' and a matching 'client\_name' field.  If the secret does not currently exist it will:
	
		1. Register the application with Verify for the tenant which is contained in the custom resource corresponding to the `verify.ibm.com/cr.name` annotation.  If the annotation is missing the tenant located in the first located 'IBMSecurityVerify' custom resource will be used.
	
		2. Save the generated client ID and secret to a new Kubernetes secret.
	
		> Details on dynamic client registration can be found at the following URLs:
	   > 
	   >   - [https://www.ibm.com/docs/en/security-verify?topic=applications-openid-connect-dynamic-client-registration#t_dynamic_kc](https://www.ibm.com/docs/en/security-verify?topic=applications-openid-connect-dynamic-client-registration#t_dynamic_kc)
	   >   - [https://docs.verify.ibm.com/verify/reference/handledeviceauthorize#handleclientregistrationpost ](https://docs.verify.ibm.com/verify/reference/handledeviceauthorize#handleclientregistrationpost)

	2. Add the annotations, via a PATCH operation, to configure the Nginx Ingress operator to call out to the OIDC server to perform OIDC authentication.

	> The following blog contains a good description on how to create a mutating Webhook controller: [https://medium.com/ovni/writing-a-very-basic-kubernetes-mutating-admission-webhook-398dbbcb63ec](https://medium.com/ovni/writing-a-very-basic-kubernetes-mutating-admission-webhook-398dbbcb63ec)

### Nginx Annotations

The following blog contains a good description of how to configure the Nginx Ingress controller for OIDC authentication: [https://developer.okta.com/blog/2018/08/28/nginx-auth-request#configure-your-protected-nginx-host](https://developer.okta.com/blog/2018/08/28/nginx-auth-request#configure-your-protected-nginx-host).

The following annotations will need to be added to the ingress definition by the mutating Webhook:

```yaml
metadata:
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.org/server-snippets: |
	    location = /verify-oidc {
	      proxy_pass https://ibm-security-verify-operator-oidc-server.default.svc.cluster.local:7443/auth;
	      proxy_pass_request_body off;
	
	      proxy_set_header Content-Length "";
	      proxy_set_header X-Namespace default;
	      proxy_set_header X-Verify-Secret ibm-security-verify-client-6112c297-da5e-4b95-a620-1b5ea8afb822;
	      proxy_set_header X-URL-Root http://my-nginx-ingress-controller-openshift-operators.apps.scottex.cp.fyre.ibm.com/verify-oidc;
	    }

	    error_page 401 = @error401;
	
	    # If the user is not logged in, redirect them to the login URL
	    location @error401 {
	      proxy_pass https://ibm-security-verify-operator-oidc-server.default.svc.cluster.local:7443/login?url=$scheme://$http_host$request_uri;
	
	      proxy_set_header X-Namespace default;
	      proxy_set_header X-Verify-Secret ibm-security-verify-client-6112c297-da5e-4b95-a620-1b5ea8afb822;
	      proxy_set_header X-URL-Root http://my-nginx-ingress-controller-openshift-operators.apps.scottex.cp.fyre.ibm.com/verify-oidc;
	    }
            
    nginx.org/location-snippets: |
            auth_request /verify-oidc;

```


## OIDC Server

The OIDC server is responsible for the managing of the OIDC authentication flow.  The flow is desribed in the following scenario diagram:

[![Authentication Flow](images/AuthFlow.png)](https://mermaid-js.github.io/mermaid-live-editor/edit/#eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG5wYXJ0aWNpcGFudCBVc2VyXG5wYXJ0aWNpcGFudCBJbmdyZXNzIGFzIE5naW54IEluZ3Jlc3NcbnBhcnRpY2lwYW50IE9wZXJhdG9yIGFzIFZlcmlmeSBPcGVyYXRvclxucGFydGljaXBhbnQgQXBwbGljYXRpb25cbnBhcnRpY2lwYW50IFZlcmlmeVxuICAgIFVzZXItPj4rSW5ncmVzczogUmVzb3VyY2UgUmVxdWVzdFxuICAgIG5vdGUgb3ZlciBJbmdyZXNzOiBOZ2lueCBkZXRlY3RzIHRoYXQgPGJyPmF1dGhlbnRpY2F0aW9uIGlzIHJlcXVpcmVkLlxuICAgIEluZ3Jlc3MtPj5PcGVyYXRvcjogR0VUIC92ZXJpZnktb2lkYy9hdXRoXG4gICAgYWN0aXZhdGUgT3BlcmF0b3JcbiAgICBPcGVyYXRvci0-PkluZ3Jlc3M6IDQwMSBGb3JiaWRkZW5cbiAgICBJbmdyZXNzLT4-T3BlcmF0b3I6IEdFVCAvdmVyaWZ5LW9pZGMvbG9naW5cbiAgICBub3RlIHJpZ2h0IG9mIE9wZXJhdG9yOiBUaGUgb3BlcmF0b3IgZ2VuZXJhdGVzIDxicj50aGUgT0lEQyByZXF1ZXN0LlxuICAgIE9wZXJhdG9yLT4-VXNlcjogMzAyIFJlZGlyZWN0XG4gICAgZGVhY3RpdmF0ZSBPcGVyYXRvclxuICAgIFVzZXItPj4rVmVyaWZ5OiBBdXRob3JpemF0aW9uIEVuZHBvaW50XG4gICAgbm90ZSByaWdodCBvZiBWZXJpZnk6IFZlcmlmeSBwZXJmb3JtcyA8YnI-YXV0aGVudGljYXRpb25cbiAgICBWZXJpZnktPj4tVXNlcjogMzAyIFJlZGlyZWN0XG4gICAgVXNlci0-PitPcGVyYXRvcjogR0VUIC92ZXJpZnktb2lkYy9hdXRoXG4gICAgT3BlcmF0b3ItPj4rVmVyaWZ5OiBUb2tlbiBFbmRwb2ludFxuICAgIFZlcmlmeS0-Pi1PcGVyYXRvcjogVG9rZW5zXG4gICAgbm90ZSByaWdodCBvZiBPcGVyYXRvcjogVGhlIG9wZXJhdG9yIHZhbGlkYXRlczxicj50aGUgdG9rZW5cbiAgICBPcGVyYXRvci0-Pi1Vc2VyOiAzMDIgUmVkaXJlY3RcbiAgICBVc2VyLT4-K0luZ3Jlc3M6IFJlc291cmNlIFJlcXVlc3RcbiAgICBhY3RpdmF0ZSBVc2VyXG4gICAgbm90ZSBvdmVyIEluZ3Jlc3M6IE5naW54IGRldGVjdHMgdGhhdCA8YnI-YXV0aGVudGljYXRpb24gaXMgcmVxdWlyZWQuXG4gICAgSW5ncmVzcy0-Pk9wZXJhdG9yOiBHRVQgL3ZlcmlmeS1vaWRjL2F1dGhcbiAgICBPcGVyYXRvci0-PkluZ3Jlc3M6IDIwMCBPS1xuICAgIEluZ3Jlc3MtPj5BcHBsaWNhdGlvbjogUmVzb3VyY2UgUmVxdWVzdFxuICAgIEFwcGxpY2F0aW9uLT4-VXNlcjogUmVzb3VyY2UgUmVzcG9uc2VcbiAgICBkZWFjdGl2YXRlIFVzZXJcbiAgICAgICAgICAgICIsIm1lcm1haWQiOiJ7XG4gIFwidGhlbWVcIjogXCJkZWZhdWx0XCJcbn0iLCJ1cGRhdGVFZGl0b3IiOmZhbHNlLCJhdXRvU3luYyI6dHJ1ZSwidXBkYXRlRGlhZ3JhbSI6ZmFsc2V9)

The following endpoints are used by the controller:

|Endpoint|Description
|--------|-----------
|/login|This is the kick-off URL for the authentication processing.  It will handle the generation of the redirect to IBM Security Verify for authentication.
|/auth|This endpoint is the main endpoint for the authentication processing.  It will mostly handle the validation of the supplied OIDC JWT after the authentication has completed.


The [Vouch Proxy](https://github.com/vouch/vouch-proxy) project contains an example OIDC-RP implementation which can be referenced for the implementation of this controller.  The [github.com/coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc#section-readme) package will be used to handle the OIDC specific processing.

