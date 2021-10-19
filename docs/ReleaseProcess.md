# Introduction

This document contains the release process which should be followed when generating a new release of the IBM Security Verify operator.

## Version Number

The version number should be of the format: `v<year>.<month>.0`, for example: `v21.10.0`.


# Generating a GitHub Release

In order to generate a new version of the operator a new GitHub release should be created: [https://github.com/IBM-Security/verify-operator/releases/new](https://github.com/IBM-Security/verify-operator/releases/new). 

The fields for the release should be:

|Field|Description
|-----|----------- 
|Tag | The version number, e.g. `v21.10.0`
|Release title | The version number, e.g. `v21.10.0`
|Release description | The resources associated with the \<version\-number> IBM Security Verify operator release.

After the release has been created the GitHub actions workflow ([https://github.com/IBM-Security/verify-operator/actions/workflows/build.yaml](https://github.com/IBM-Security/verify-operator/actions/workflows/build.yaml)) will be executed to generate the build.  

This build process will include:

* publishing the generated docker images to DockerHub;
* adding the bundle zip to the release artifacts in GitHub.

# Testing on RedHat OpenShift

In order to test the environment on RedHat Openshift the `ibmcom/verify-operator` and `ibmcom/verify-operator-build` images on DockerHub must be up to date.  You then need to:

* Create a catalog image.  This will require a public Docker repository.  The command to create the catalog image is similar to: 

```shell
opm index add -u docker \
  --bundles docker.io/ibmcom/verify-access-operator-bundle:1.1.3 \
  --from-index quay.io/operatorhubio/catalog:latest \
  --tag docker.io/scottexton/verify-access-operator-catalog:1.1.3
```

* Add the catalog to the list of OpenShift catalogs using something similar to the following yaml file:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: my-operator-catalog
  namespace: openshift-marketplace 
spec:
  sourceType: grpc
  image: docker.io/scottexton/verify-access-operator-catalog:1.1.3
  displayName: My Operator Catalog
  publisher: Verify Operator Development
  updateStrategy:
    registryPoll: 
      interval: 30m
```
Once the CatalogSource object has been created you will be able to view and install the Operator using the OpenShift Web console.

# RedHat Operator Certification

> This section still needs to be written.

A good description of the RedHat Operator Certification process can be found at:

* [https://cloud.redhat.com/blog/red-hat-openshift-operator-certification](https://cloud.redhat.com/blog/red-hat-openshift-operator-certification).
* [https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/](https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/)

