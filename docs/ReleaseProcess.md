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
  --bundles docker.io/ibmcom/verify-operator-bundle:1.1.3 \
  --from-index quay.io/operatorhubio/catalog:latest \
  --tag docker.io/isamdev/verify-operator-catalog:1.1.3
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
  image: docker.io/isamdev/verify-operator-catalog:1.1.3
  displayName: My Operator Catalog
  publisher: Verify Operator Development
  updateStrategy:
    registryPoll: 
      interval: 30m
```
Once the CatalogSource object has been created you will be able to view and install the Operator using the OpenShift Web console.

# RedHat Operator Certification

Certification projects are managed through the [RedHat Partner Connect Portal](https://connect.redhat.com/manage/projects).  

At a high level, to certify the operator, you need to:


1. Create a 'certification project' for the operator using the RedHat Partner Connect Portal ([instructions](https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/certify-your-operator/creating-an-operator-project));
	2. Provide the details of the operator on the 'Settings' tab;
	3. Scan the new image using the 'Scan new image' button on the 'Images' tab;
2. Create a 'certification project' for the operator bundle using the RedHat Partner Connect Portal ([instructions](https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/certify-your-operator/certify-your-operator-bundle-image));
	3. Provide the details of the operator on the 'Settings' tab;
	4. Test the operator and submit a pull request.  

	> It is important that in the pull request the images contained within the cluster service version file are updated, replacing the tag name with the corresponding sha256 digest.

## Bundle Testing

As a part of the certification process you need to test your bundle.  You can do this locally, or by using the hosted pipeline.  Both mechanisms are not without problems.  

### Local Testing

Instructions on how to run the tests locally are available at: [https://github.com/redhat-openshift-ecosystem/certification-releases/blob/main/4.9/ga/ci-pipeline.md](https://github.com/redhat-openshift-ecosystem/certification-releases/blob/main/4.9/ga/ci-pipeline.md)

I was never able to successfully run the tests in my local OpenShift environment, although after a lot of trial and error I was able to make some limited progress. Some points to note about running the tests locally:

1. You need to create a default storage class (type: no-provisioner);
2. You need to create a new persistent volume using the yaml included below;
3. You need to modify the `templates/workspace-template.yaml` file to reference the new PV: `volumeName: pv0001`

```yaml
kind: PersistentVolume
apiVersion: v1
metadata:
  name: pv0001
spec:
  capacity:
    storage: 50Gi
  nfs:
    server: 10.22.82.15
    path: /data/certify
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Recycle
  storageClassName: manual
  volumeMode: Filesystem
```

### Hosted Pipeline

Instructions on how to run the tests using the hosted pipeline are available at: [https://github.com/redhat-openshift-ecosystem/certification-releases/blob/main/4.9/ga/hosted-pipeline.md](https://github.com/redhat-openshift-ecosystem/certification-releases/blob/main/4.9/ga/hosted-pipeline.md).  

Unfortunately the hosted pipeline provides no information on why a test run failed - although it should be adding this information to the project in the RedHat Partner Connect Portal ('Test results' tab).  A support ticket has been raised with the RedHat support organisation to determine what is going wrong.
