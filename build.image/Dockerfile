##############################################################################
# Copyright contributors to the IBM Security Verify Operator project
##############################################################################

# Our build image is based on the RedHat Universal Base Image (ubi)
FROM registry.access.redhat.com/ubi8/ubi:latest

# Add in our files.  
ADD root/sbin /sbin

# Execute our script which is used to prepare the image.
RUN /bin/sh /sbin/prepare.sh && rm -f /sbin/prepare.sh

# Our default entry point.
ENTRYPOINT [ "/bin/sh", "/sbin/bootstrap.sh" ]

# The volumes which we need to export.
VOLUME ["/build"]

# Some labels which will be associated with the image.
LABEL maintainer="isamdev@au.ibm.com" \
    vendor="IBM" \
    product="IBM Security Verify" \
    documentation="https://www.ibm.com/docs/en/security-verify" \
    product_information="(https://www.ibm.com/products/verify-for-workforce-iam" \
    copyright="Copyright contributors to the IBM Security Verify Operator project"

