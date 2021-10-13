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

# RedHat Operator Certification

> This section still needs to be written.

A good description of the RedHat Operator Certification process can be found at:

* [https://cloud.redhat.com/blog/red-hat-openshift-operator-certification](https://cloud.redhat.com/blog/red-hat-openshift-operator-certification).
* [https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/](https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/)

