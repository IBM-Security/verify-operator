# Copyright contributors to the IBM Security Verify Operator project

# Build the manager binary
FROM golang:1.16 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY *.go /workspace/
COPY api/ api/
COPY controllers/ controllers/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager main.go ingress_webhook.go oidc_server.go constants.go utils.go lru_store.go

# In order to get this operator certified by RedHat it needs to be based on
# RedHat UBI.
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

### Required OpenShift Labels
LABEL name="IBM Security Verify Operator" \
      vendor="IBM" \
      version="v--version--" \
      release="1" \
      summary="This operator adds IBM Security Verify authentication support to your Ingress services." \
      description="The IBM Security Verify operator can consistently enforce policy-driven security by using the Ingress networking capability of OpenShift, in conjunction with the Nginx Ingress operator. With this approach, you can enforce authentication and authorization policies for all of the applications in your cluster at the same time, without ever changing your application code. You can also dynamically register your application to start protecting them centrally from the cloud via IBM Security Verify SaaS."

# Required Licenses
COPY licenses /licenses

ENTRYPOINT ["/manager"]
