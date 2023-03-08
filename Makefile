GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := "ghcr.io/wouldgo/name-dot-com-webhook"
IMAGE_TAG := "0.1.1"

OUT := $(shell pwd)/_out

KUBEBUILDER_VERSION=2.3.2

$(shell mkdir -p "$(OUT)")

test: _test/kubebuilder
	TEST_ZONE_NAME=example.com. \
	TEST_ASSET_ETCD=_test/kubebuilder/bin/etcd \
	TEST_ASSET_KUBE_APISERVER=_test/kubebuilder/bin/kube-apiserver \
	TEST_ASSET_KUBECTL=_test/kubebuilder/bin/kubectl \
	$(GO) test -v .

_test/kubebuilder:
	curl -fsSL https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_${KUBEBUILDER_VERSION}_${OS}_${ARCH}.tar.gz -o kubebuilder-tools.tar.gz
	mkdir -p _test/kubebuilder
	tar -xvf kubebuilder-tools.tar.gz
	mv kubebuilder_${KUBEBUILDER_VERSION}_${OS}_${ARCH}/bin _test/kubebuilder/
	rm kubebuilder-tools.tar.gz
	rm -R kubebuilder_${KUBEBUILDER_VERSION}_${OS}_${ARCH}

clean: clean-kubebuilder

clean-kubebuilder:
	rm -Rf _test/kubebuilder

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
		--name example-webhook \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		deploy/example-webhook > "$(OUT)/rendered-manifest.yaml"
