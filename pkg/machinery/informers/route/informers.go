package kube

import (
	routeclientset "github.com/openshift/client-go/route/clientset/versioned"
	routeinformers "github.com/openshift/client-go/route/informers/externalversions"
)

type Interface interface {
	Start(stopCh <-chan struct{})
	InformersFor(namespace string) routeinformers.SharedInformerFactory
	Namespaces() []string
}

type routeInformersForNamespaces map[string]routeinformers.SharedInformerFactory

var _ Interface = routeInformersForNamespaces{}

func NewRouteInformersForNamespaces(routeClient routeclientset.Interface, namespaces []string) routeInformersForNamespaces {
	res := routeInformersForNamespaces{}

	for _, namespace := range namespaces {
		res[namespace] = routeinformers.NewSharedInformerFactoryWithOptions(routeClient, 0, routeinformers.WithNamespace(namespace))
	}

	return res
}

func (i routeInformersForNamespaces) Start(stopCh <-chan struct{}) {
	for _, informer := range i {
		informer.Start(stopCh)
	}
}

func (i routeInformersForNamespaces) Namespaces() []string {
	var ns []string
	for n, _ := range i {
		ns = append(ns, n)
	}
	return ns
}
func (i routeInformersForNamespaces) InformersFor(namespace string) routeinformers.SharedInformerFactory {
	return i[namespace]
}

func (i routeInformersForNamespaces) HasInformersFor(namespace string) bool {
	return i.InformersFor(namespace) != nil
}
