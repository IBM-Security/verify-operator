# Nginx Ingress Setup

## Overview

The Nginx Ingress operator, provided by ngxinc, must be configured as the Ingress controller into the OpenShift environment.  The Verify operator can only protect traffic which has been ingressed through this operator.  This document provides high level instructions on how to deploy and use the Nginx Ingress operator.

> Note: The ngxinc Nginx Ingress operator is different to the standard Kubernetes Nginx Ingress operator.  The standard Kubernetes Nginx Ingress operator is not supported in an OpenShift environment.

## Installation

The following blog contains step-by-step instructions on how to install the Nginx Ingress operator into an OpenShift environment: [https://www.nginx.com/blog/getting-started-nginx-ingress-operator-red-hat-openshift/](https://www.nginx.com/blog/getting-started-nginx-ingress-operator-red-hat-openshift/).

In step 7 of the blog an example custom resource is provided for the configuration of the operator.  This example will cause a 'LoadBalancer' service to be created for the Ingress controller.  This works well in a cloud environment which supports a 'LoadBalancer' service, but doesn't work so well in an on-premise deployment of OpenShift.  The following yaml shows an alternative custom resource which causes a 'NodePort' service to be created:

```yaml
apiVersion: k8s.nginx.org/v1alpha1
kind: NginxIngressController
metadata:
  name: my-nginx-ingress-controller
  namespace: openshift-operators
spec:
  type: deployment
  nginxPlus: false
  image:
    repository: docker.io/nginx/nginx-ingress
    tag: 1.12.0-ubi
    pullPolicy: Always
  replicas: 1
  serviceType: NodePort
  
  # Uncomment the following two lines to enable debugging
  # within the Nginx controller.
  # nginxDebug: true
  # logLevel: 3
```

## Route

If you are using a NodePort service for the operator you also need to create a route for the service so that traffic can ingress into the operator.  The following command can be executed to create the route:

```shell
oc expose service my-nginx-ingress-controller -n openshift-operators
```

In order to determine the host name for the route you need to examine the 'host' field from the route definition:

```shell
oc get route my-nginx-ingress-controller -n openshift-operators -o jsonpath='{.spec.host}'
```

You can then test that the Nginx Ingress operator is reachable using something like curl:

```shell
curl http://my-nginx-ingress-controller-openshift-operators.apps.scotte.cp.fyre.ibm.com/
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.21.0</center>
</body>
</html>
```

## Test Application

In order to fully test the installation you can create a test application and then an Ingress definition to that test application.  The easiest test application to use is the `hello-openshift` application.

To deploy the application use the following deployment descriptor:

```yaml
apiVersion: apps/v1
kind: Deployment

metadata:
  name: hello-openshift
  labels:
    app: hello-openshift

spec:
  selector:
    matchLabels:
      app: hello-openshift

  replicas: 1
  template:
    metadata:
      labels:
        app: hello-openshift

    spec:
      containers:
      - name: hello-openshift
        image: openshift/hello-openshift:latest
        ports:
        - containerPort: 8080
```

You then need to create a ClusterIP service for the deployment:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: hello-openshift
spec:
  ports:
    - port: 8080
  selector:
    app: hello-openshift
```

You then need to create the Ingress definition for the service:

```yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: hello-openshift
  annotations:
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
  - host: my-nginx-ingress-controller-openshift-operators.apps.scotte.cp.fyre.ibm.com
    http:
      paths:
      - path: /hello-openshift
        backend:
          serviceName: hello-openshift
          servicePort: 8080
```

After this you should be able to access the service via the Nginx ingress controller:

```shell
curl http://my-nginx-ingress-controller-openshift-operators.apps.scotte.cp.fyre.ibm.com/hello-openshift
Hello OpenShift!
```

You now have the Nginx Ingress controller installed and configured for the environment, and are now ready to install and use the IBM Security Verify operator.