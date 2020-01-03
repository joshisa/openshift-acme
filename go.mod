module github.com/tnozicka/openshift-acme

go 1.13

require (
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.2-0.20191230164726-a31eda7afd3c
	github.com/openshift/api v0.0.0-20200102191951-7e36eed0d19e
	github.com/openshift/client-go v0.0.0-20191219165006-ac3b642258cc
	github.com/openshift/library-go v0.0.0-20200103144857-38e0f6451b16
	github.com/prometheus/client_golang v1.3.0
	github.com/spf13/cobra v0.0.6-0.20191226175542-bf2689566459
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.0.0-20191227163750-53104e6ec876
	gopkg.in/yaml.v2 v2.2.7
	k8s.io/api v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/apiserver v0.17.0
	k8s.io/client-go v0.17.0
	k8s.io/klog v1.0.0
)
