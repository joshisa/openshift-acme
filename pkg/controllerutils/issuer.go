package controllerutils

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	_ "github.com/openshift/client-go/route/clientset/versioned/scheme"
	"github.com/tnozicka/openshift-acme/pkg/api"
	kubeinformers "github.com/tnozicka/openshift-acme/pkg/machinery/informers/kube"
)

func getIssuerConfigMapsForObject(obj metav1.ObjectMeta, globalIssuerNamesapce string, kubeInformersForNamespaces kubeinformers.Interface) ([]*corev1.ConfigMap, error) {
	// Lookup explicitly referenced issuer first. If explicitly referenced this should be the only match.
	issuerName, found := obj.Annotations[api.AcmeCertIssuerName]
	if found && len(issuerName) > 0 {
		issuerConfigMap, err := kubeInformersForNamespaces.InformersForOrGlobal(obj.Namespace).Core().V1().ConfigMaps().Lister().ConfigMaps(obj.Namespace).Get(issuerName)
		if err != nil {
			return nil, fmt.Errorf("can't get issuer %s/%s: %w", obj.Namespace, issuerName, err)
		}
		return []*corev1.ConfigMap{issuerConfigMap}, nil
	}

	var issuerConfigMaps []*corev1.ConfigMap

	localConfigMapList, err := kubeInformersForNamespaces.InformersForOrGlobal(obj.Namespace).Core().V1().ConfigMaps().Lister().ConfigMaps(obj.Namespace).List(api.AccountLabelSet.AsSelector())
	if err != nil {
		return nil, fmt.Errorf("can't look up local issuers: %w", err)
	}
	issuerConfigMaps = append(issuerConfigMaps, localConfigMapList...)

	globalConfigMapList, err := kubeInformersForNamespaces.InformersForOrGlobal(globalIssuerNamesapce).Core().V1().ConfigMaps().Lister().ConfigMaps(globalIssuerNamesapce).List(api.AccountLabelSet.AsSelector())
	if err != nil {
		return nil, fmt.Errorf("can't look up global issuers: %w", err)
	}
	issuerConfigMaps = append(issuerConfigMaps, globalConfigMapList...)

	if len(issuerConfigMaps) < 1 {
		return nil, fmt.Errorf("can't find any issuer")
	}

	sort.Slice(issuerConfigMaps, func(i, j int) bool {
		lhs := issuerConfigMaps[i]
		rhs := issuerConfigMaps[i]

		lhsPrio := 0
		lhsPrioString, ok := lhs.Annotations[api.AcmePriorityAnnotation]
		if ok && len(lhsPrioString) != 0 {
			v, err := strconv.Atoi(lhsPrioString)
			if err == nil {
				lhsPrio = v
			} else {
				klog.Warning(err)
			}
		}

		rhsPrio := 0
		rhsPrioString, ok := rhs.Annotations[api.AcmePriorityAnnotation]
		if ok && len(rhsPrioString) != 0 {
			v, err := strconv.Atoi(rhsPrioString)
			if err == nil {
				rhsPrio = v
			} else {
				klog.Warning(err)
			}
		}

		if lhsPrio < rhsPrio {
			return true
		}

		if lhs.CreationTimestamp.Time.After(rhs.CreationTimestamp.Time) {
			return true
		}

		return false
	})

	return issuerConfigMaps, nil
}

func IssuerForObject(obj metav1.ObjectMeta, globalIssuerNamespace string, kubeInformersForNamespaces kubeinformers.Interface) (*api.CertIssuer, *corev1.Secret, error) {
	issuerConfigMaps, err := getIssuerConfigMapsForObject(obj, globalIssuerNamespace, kubeInformersForNamespaces)
	if err != nil {
		return nil, nil, err
	}

	// TODO: Filter out non-matching issuers and solvers
	certIssuerCM := issuerConfigMaps[0]

	certIssuerData, ok := certIssuerCM.Data[api.CertIssuerDataKey]
	if !ok {
		return nil, nil, fmt.Errorf("configmap %s/%s is matching CertIssuer selectors %q but missing key %q", obj.Namespace, obj.Name, api.AccountLabelSet, api.CertIssuerDataKey)
	}

	certIssuer := &api.CertIssuer{}
	err = yaml.Unmarshal([]byte(certIssuerData), certIssuer)
	if err != nil {
		return nil, nil, fmt.Errorf("configmap %s/%s is matching CertIssuer selectors %q but contains invalid object: %w", obj.Namespace, obj.Name, api.AccountLabelSet, err)
	}

	if len(certIssuer.SecretName) == 0 {
		return certIssuer, nil, nil
	}

	secret, err := kubeInformersForNamespaces.InformersForOrGlobal(certIssuerCM.Namespace).Core().V1().Secrets().Lister().Secrets(certIssuerCM.Namespace).Get(certIssuer.SecretName)
	if err != nil {
		return nil, nil, err
	}

	return certIssuer, secret, nil
}
