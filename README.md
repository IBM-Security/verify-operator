# IBM Security Verify Operator


- [Overview](#overview)
  * [Prerequisites](#prerequisites)
  * [Restrictions](#restrictions)
- [Architecture](#architecture)
  * [Components](#components)
  * [Flow](#flow)
- [Installation](#installation)
  * [Procedure](#procedure)
- [Configuration](#configuration)
  * [Secrets](#secrets)
  * [Configuring the Operator](#configuring-the-operator)
- [Usage](#usage)
  * [Creating a new Application](#creating-a-new-application)
    + [Self Registration](#self-registration)
    + [Manual Registration](#manual-registration)
  * [Creating an Ingress Resource](#creating-an-ingress-resource)


## Overview

[IBM Security Verify](https://www.ibm.com/products/verify-saas) is an Identity-as-a-Service platform that allows IT, security and business leaders to protect their digital users, assets and data in a hybrid, multi-cloud world by enabling technical agility and operational efficiency. IBM Security Verify SaaS provides single sign-on (SSO), multi-factor authentication (MFA), AI-powered context for risk-based authentication for adaptive access decisions, user management, access recertification campaigns and identity analytics.
 
For a detailed description of IBM Security Verify refer to the [Offical documentation](https://www.ibm.com/docs/en/security-verify).

The IBM Security Verify operator can consistently enforce policy-driven security by using the Ingress networking capability of OpenShift. With this approach, you can enforce authentication and authorization policies for all of the applications in your cluster at the same time, without ever changing your application code.  You can also dynamically register your application to start protecting them centrally from the cloud via Verify SaaS. 

### Prerequisites

The are a number of prerequisites which must be met before the Verify operator can be installed and used, namely:

1. The operator supports the [RedHat OpenShift](https://www.redhat.com/en/technologies/cloud-computing/openshift) containerized environment and does not currently support other Kubernetes environments.  
2. The RedHat certificated [Nginx Ingress operator](https://catalog.redhat.com/software/operators/detail/5e9874913f398525a0ceb00d) must be installed and the applications which are to be protected by IBM Security Verify must be accessed by the service which is provided by the Ingress controller.  Please note that this operator is different to the standard Kubernetes Nginx Ingress operator.  
3. An IBM Security Verify tenant is required to provide authentication and adaptive access capabilities.  A free trial tenant is available and can be requested by clicking on the `Try free edition` button on the [Verify product page](https://www.ibm.com/docs/en/security-verify).

> XXX: Still need to find out information on the creation of the OpenShift tenant.

### Restrictions

The restrictions on the usage of the operator include:

1. Only traffic which passes through the Nginx Ingress operator will be protected.  Any traffic which uses the native OpenShift Route or Ingress controller will not be protected.
2. The authorization-code flow is the only OIDC authentication flow which is supported.

## Architecture

### Components

The following diagram depicts the components which are used in the environment.  The 'OpenShift Route Operator' is not necessarily required in a cloud environment as the native cloud Load Balancer could be used as an alternative mechanism to ingress into the environment.

![Components](docs/images/Components.png)

### Flow

OpenID Connect (OIDC) is used in the environment to pass single sign-on information from IBM Security Verify into the OpenShift environment.  The OIDC specification states that authentication can follow one of three paths: the Authorization Code Flow, the Implicit Flow, or the Hybrid Flow. The flow determines how the ID Token and Access Token are returned to the Client. The IBM Security Verify operator will only support the Authorization Code Flow, and the overall flow, incorporating single sign-on from IBM Security Verify, is described in the following scenario diagram.

[![Authentication Flow](docs/images/AuthFlow.png)](https://mermaid-js.github.io/mermaid-live-editor/edit##eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG5wYXJ0aWNpcGFudCBVc2VyXG5wYXJ0aWNpcGFudCBJbmdyZXNzIGFzIE5naW54IEluZ3Jlc3NcbnBhcnRpY2lwYW50IE9wZXJhdG9yIGFzIFZlcmlmeSBPcGVyYXRvclxucGFydGljaXBhbnQgQXBwbGljYXRpb25cbnBhcnRpY2lwYW50IFZlcmlmeVxuICAgIFVzZXItPj4rSW5ncmVzczogUmVzb3VyY2UgUmVxdWVzdFxuICAgIG5vdGUgb3ZlciBJbmdyZXNzOiBOZ2lueCBkZXRlY3RzIHRoYXQgPGJyPmF1dGhlbnRpY2F0aW9uIGlzIHJlcXVpcmVkLlxuICAgIEluZ3Jlc3MtPj5PcGVyYXRvcjogR0VUIC92ZXJpZnktb2lkYy9jaGVja1xuICAgIGFjdGl2YXRlIE9wZXJhdG9yXG4gICAgT3BlcmF0b3ItPj5JbmdyZXNzOiAzMDIgL3ZlcmlmeS1vaWRjL2F1dGhcbiAgICBJbmdyZXNzLT4-T3BlcmF0b3I6IEdFVCAvdmVyaWZ5LW9pZGMvYXV0aFxuICAgIG5vdGUgcmlnaHQgb2YgT3BlcmF0b3I6IFRoZSBvcGVyYXRvciBnZW5lcmF0ZXMgPGJyPnRoZSBPSURDIHJlcXVlc3QuXG4gICAgT3BlcmF0b3ItPj5Vc2VyOiAzMDIgUmVkaXJlY3RcbiAgICBkZWFjdGl2YXRlIE9wZXJhdG9yXG4gICAgVXNlci0-PitWZXJpZnk6IEF1dGhvcml6YXRpb24gRW5kcG9pbnRcbiAgICBub3RlIHJpZ2h0IG9mIFZlcmlmeTogVmVyaWZ5IHBlcmZvcm1zIDxicj5hdXRoZW50aWNhdGlvblxuICAgIFZlcmlmeS0-Pi1Vc2VyOiAzMDIgUmVkaXJlY3RcbiAgICBVc2VyLT4-K09wZXJhdG9yOiBHRVQgL3ZlcmlmeS1vaWRjL2F1dGhcbiAgICBPcGVyYXRvci0-PitWZXJpZnk6IFRva2VuIEVuZHBvaW50XG4gICAgVmVyaWZ5LT4-LU9wZXJhdG9yOiBUb2tlbnNcbiAgICBub3RlIHJpZ2h0IG9mIE9wZXJhdG9yOiBUaGUgb3BlcmF0b3IgdmFsaWRhdGVzPGJyPnRoZSB0b2tlblxuICAgIE9wZXJhdG9yLT4-LVVzZXI6IDMwMiBSZWRpcmVjdFxuICAgIFVzZXItPj4rQXBwbGljYXRpb246IFJlc291cmNlIFJlcXVlc3RcbiAgICBBcHBsaWNhdGlvbi0-Pi1Vc2VyOiBSZXNvdXJjZSBSZXNwb25zZVxuICAgICAgICAgICAgIiwibWVybWFpZCI6IntcbiAgXCJ0aGVtZVwiOiBcImRlZmF1bHRcIlxufSIsInVwZGF0ZUVkaXRvciI6ZmFsc2UsImF1dG9TeW5jIjp0cnVlLCJ1cGRhdGVEaWFncmFtIjpmYWxzZX0)


## Installation

Kubernetes operators are very useful tools that provide lifecycle management capabilities for many varying custom objects in Kubernetes. The [RedHat Operator Catalog](https://catalog.redhat.com/software/operators/search) provides a single place where Kubernetes administrators or developers can go to find existing operators that may provide the functionality that they require in an OpenShift environment. 

The information provided by the [RedHat Operator Catalog](https://catalog.redhat.com/software/operators/search) allows the Operator Lifecycle Manager (OLM) to manage the operator throughout its complete lifecycle. This includes the initial installation and subscription to the RedHat Operator Catalog such that updates to the operator can be performed automatically.

### Procedure

To install the IBM Security Verify operator from the RedHat Operator Catalog:

1. Log into the OpenShift console as an administrator.
2. In the left navigation column, click Operators and then OperatorHub. Type 'verify-operator' in the search box, and click on the IBM Security Verify Operator box that appears.
![OpenShift Operator Search](docs/images/OpenShiftOperatorSearch.png)
3. After reviewing the product information, click the `Install` button.
![OpenShift Operator Info](docs/images/OpenShiftOperatorProductInfo.png)
4. On the 'Install Operator' page that opens, specify the cluster namespace in which to install the operator. Also click the `Automatic` radio button under Approval Strategy, to enable automatic updates of the running Operator instance without manual approval from the administrator. Click the `Install` button.
![OpenShift Operator Subscription](docs/images/OpenShiftOperatorSubscription.png)
5. Ensure that the IBM Security Verify operator has been created by the Operator Lifecycle Manager. The phase should be set to "Succeeded". Note that this may take a few minutes.

```shell
oc get csv -n openshift-operators

NAME                                    DISPLAY                        VERSION   REPLACES   PHASE
ibm-security-verify-operator.v21.10.0   IBM Security Verify Operator   21.10.0              Succeeded
``` 

At this point the IBM Security Verify operator has been deployed and a subscription has been created that will monitor for any updates to the operator in the RedHat Operator Catalog. The IBM Security Verify operator is now operational.

## Configuration

Before the operator can be used it must be configured with information which is specific to the running OpenShift environment.  Two steps must be completed in order to configure the operator:

1. Create the secret which contains the IBM Security Verify client credentials;
2. Create the IBMSecurityVerify custom resource for the IBM Security Verify tenant.

### Secrets

A Kubernetes secret is used by the operator controller to store sensitive information. This secret must be created in the Kubernetes namespace in which the IBM Security Verify operator is running. 

The secret includes the following data fields:

| Field | Description
| ----- | -----------
| client\_name | The name of the IBM Security Verify client which will be used to create OIDC single sign-on applications.
| client\_id | The ID of the IBM Security Verify client which will be used to create OIDC single sign-on applications.
| client\_secret | The associated secret of the IBM Security Verify client which be used to create OIDC single sign-on applications.
| discovery\_endpoint | The discovery endpoint, which returns a JSON listing of the OpenID/OAuth endpoints, for the IBM Security Verify tenant.

The following example (verify-secret.yaml) shows a secret definition:

```yaml
kind: Secret 
apiVersion: v1

metadata:
  name: ibm-security-verify-client-1cbfe647-9e5f-4d99-8e05-8ec1c862eb47
  labels:
    product: ibm-security-verify
type: opaque
data: 
  client_name: bXktb3BlbnNoaWZ0LWNsaWVudAo=
  client_id: MWNiZmU2NDctOWU1Zi00ZDk5LThlMDUtOGVjMWM4NjJlYjQ3Cg==
  client_secret: WllEUExMQldTSzNNVlFKU0lZSEIxT1IySlhDWTBYMkM1VUoyUUFSMk1BQUlUNVEK
  discovery_endpoint: aHR0cHM6Ly90ZXN0X3RlbmFudC52ZXJpZnkuaWJtLmNvbS9vaWRjL2VuZHBvaW50L2RlZmF1bHQvLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24K
```

The following command can be used to create the secret from this file:

```shell
oc apply -f verify-secret.yaml -n operators
```

The secret can either be created manually or the yaml definition can be downloaded from the IBM Security Verify console and then applied in the OpenShift environment.

> XXX: Still need to confirm the format of the secret, and find further information on how to obtain the YAML from the console.

### Configuring the Operator

In order to configure the operator for a specific IBM Security Verify tenant an IBMSecurityVerify custom resource must be created.  This custom resource must be created in the Kubernetes namespace in which the IBM Security Verify operator is running. 

The following example (ibm-security-verify.yaml) shows an IBMSecurityVerify custom resource:

```yaml
apiVersion: ibm.com/v1
kind: IBMSecurityVerify

metadata:
  name: verify-test-tenant
  namespace: openshift-operators

spec:
  # The name of the secret which contains the IBM Security Verify
  # client credentials.
  clientSecret: ibm-security-verify-client-1cbfe647-9e5f-4d99-8e05-8ec1c862eb47
```

The following command can be used to create the custom resource from this file:

```shell
oc apply -f ibm-security-verify.yaml 
```

## Usage

### Creating a new Application

In order to protect an Ingress service it must first be registered with IBM Security Verify as an 'Application'.  This registration can be a manual process, or if the application is not yet known to the operator a new application will be automatically registered with IBM Security Verify when the Ingress service is created.

#### Self Registration

When an unknown IBM Security Verify Application is specified in the Ingress resource definition (i.e. the specified application does not correspond to a well-defined Kubernetes secret) the operator will automatically register the application with IBM Security Verify using the configured tenant information.

When registering the application the operator will use the following fields:

|Field|Value
|-----|-----
|Name|The name specified in the corresponding annotation from the Ingress definition.
|Application URL|The URL associated with the application, as obtained from the corresponding annotation in the Ingress definition.
|Sign-on method|Open ID Connect 1.0
|Grant types|Authorization code 
|User consent|The user consent field, as obtained from the corresponding annotation in the Ingress definition.
|Redirect URIs|The valid redirect URL's, obtained from the `Host` fields within the rules of the Ingress definition.

#### Manual Registration

Further information on how to register a custom 'application' is available in the official IBM Security Verify documentation: [https://www.ibm.com/docs/en/security-verify?topic=applications-custom-application#custom_application](https://www.ibm.com/docs/en/security-verify?topic=applications-custom-application#custom_application).  

The following fields should be set when registering the application:

|Field|Value
|-----|-----
|Sign-on method|Open ID Connect 1.0
|Grant types|Authorization code 
|Client authentication method|Client secret basic
|Redirect URIs|https://\<nginx-ingress-url\>/verify-oidc

Once the application has been registered a new secret will need to be created in the same OpenShift namespace as the IBM Security Verify operator.  The name of the secret should be of the format: 'ibm\-security\-verify\-client\-\<client\-id>', and consist of the following fields:

|Field|Value
|-----|-----  
| metadata.labels.product | 'ibm-security-verify'
| data.client_name | The name of the client (aka application).
| data.client\_id | The ID of the client which will be used to single sign-on to the application.
| data.client\_secret | The associated secret of the client which be used to single-sign-on to the application.
| data.discovery\_endpoint | The discovery endpoint, which returns a JSON listing of the OpenID/OAuth endpoints, for the IBM Security Verify tenant.

The following example (verify-app-testapp.yaml) shows a secret definition:

```yaml
kind: Secret 
apiVersion: v1

metadata:
  name: ibm-security-verify-client-1cbfe647-9e5f-4d99-8e05-8ec1c862eb47
  labels:
    product: ibm-security-verify
type: opaque
data: 
  client_name: bXktb3BlbnNoaWZ0LWFwcGxpY2F0aW9uCg==
  client_id: MWNiZmU2NDctOWU1Zi00ZDk5LThlMDUtOGVjMWM4NjJlYjQ3Cg==
  client_secret: WllEUExMQldTSzNNVlFKU0lZSEIxT1IySlhDWTBYMkM1VUoyUUFSMk1BQUlUNVEK
  discovery_endpoint: aHR0cHM6Ly90ZXN0X3RlbmFudC52ZXJpZnkuaWJtLmNvbS9vaWRjL2VuZHBvaW50L2RlZmF1bHQvLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24K
```

The following command can be used to create the secret from this file:

```shell
oc apply -f verify-app-testapp.yaml -n operators
```

The secret can either be created manually or the yaml definition can be downloaded from the IBM Security Verify console and then applied in the OpenShift environment.

> XXX: The ability to download the application secret yaml is another good option to add to the Verify console.


### Creating an Ingress Resource

When creating an Ingress resource a few additional metadata annotations must be included in the definition:

|Annotation|Description|Required
|----------|-----------|--------
|verify.ibm.com/app.name|This annotation is used by the IBM Security Verify operator to determine which IBM Security Verify Application the requests should be authenticated by.  It will correspond to a secret which contains the client credentials for the Application.  Existing secrets will be searched for a 'product' label of 'ibm-security-verify' and a matching 'client\_name'.  If the secret does not already exist the application will be automatically registered with IBM Security Verify, and the credential information will be stored in the secret for future reference.| Yes
|verify.ibm.com/cr.name|This optional annotation contains the name of the IBMSecurityVerify custom resource for the Verify tenant which is to be used.  This field is only required if multiple IBMSecurityVerify custom resources have been created, and the application has not already been registered with IBM Security Verify.| Required if the application has not already been registered.
|verify.ibm.com/app.url|This optional annotation is used during the registration of the Application with IBM Security Verify and indicates the URL for the application.  This URL is used when launching the application from the IBM Security Verify dashboard. | Required if the application has not already been registered.
|verify.ibm.com/consent.action|This optional annotation is used during the registration of the Application with IBM Security Verify and indicates the user consent setting.  The valid values are: ‘never\_prompt’ or ‘always\_prompt’| No
|verify.ibm.com/protocol|The protocol which is used when accessing this ingress resource.  This will be used in the construction of the redirect URI's which are registered with IBM Security Verify.  The valid options are: `http`,`https`,`both`.  If no value is specified a default value of `https` will be used.| No

The following example (testapp.yaml) shows an Ingress definition:

```yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress

metadata:
  name: testapp
  annotations:
    verify.ibm.com/app.name: "my-openshift-application"
    verify.ibm.com/cr.name: "verify-test-tenant"
    verify.ibm.com/app.url: "https://my-nginx-ingress.apps.acme.ibm.com/home"
    verify.ibm.com/consent.action: "always_prompt"
    verify.ibm.com/protocol: "https"
spec:
  rules:
  - host: my-nginx-ingress.apps.acme.ibm.com
    http:
      paths:
      - path: /testapp
        backend:
          serviceName: testapp
          servicePort: 8080
```

The following command can be used to create the Ingress definition from this file:

```shell
oc apply -f testapp.yaml
```
