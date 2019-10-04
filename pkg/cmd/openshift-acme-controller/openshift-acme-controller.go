package openshift_acme_controller

import (
	"context"
	"flag"
	"fmt"
	"strings"

	routeclientset "github.com/openshift/client-go/route/clientset/versioned"
	routeinformersv1 "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	"github.com/spf13/cobra"
	kvalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/errors"
	kcoreinformersv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kcorelistersv1 "k8s.io/client-go/listers/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"github.com/tnozicka/openshift-acme/pkg/acme/challengeexposers"
	acmeclientbuilder "github.com/tnozicka/openshift-acme/pkg/acme/client/builder"
	"github.com/tnozicka/openshift-acme/pkg/cmd/genericclioptions"
	cmdutil "github.com/tnozicka/openshift-acme/pkg/cmd/util"
	routecontroller "github.com/tnozicka/openshift-acme/pkg/controllers/route"
	"github.com/tnozicka/openshift-acme/pkg/signals"
)

type Options struct {
	genericclioptions.IOStreams

	Workers           int
	Kubeconfig        string
	Namespaces        []string
	AcmeUrl           string
	AcmeAccountSecret string

	restConfig  *restclient.Config
	kubeClient  kubernetes.Interface
	routeClient routeclientset.Interface
}

func NewOptions(streams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams:         streams,
		Workers:           10,
		Kubeconfig:        "",
		AcmeUrl:           "https://acme-staging.api.letsencrypt.org/directory",
		AcmeAccountSecret: "acme-account",
		Namespaces:        []string{metav1.NamespaceAll},
	}
}

func NewOpenshiftAcmeControllerCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(streams)

	// Parent command to which all subcommands are added.
	rootCmd := &cobra.Command{
		Use:   "openshift-acme-controller",
		Short: "openshift-acme-controller is a controller for Kubernetes (and OpenShift) which will obtain SSL certificates from ACME provider (like \"Let's Encrypt\")",
		Long:  "openshift-acme-controller is a controller for Kubernetes (and OpenShift) which will obtain SSL certificates from ACME provider (like \"Let's Encrypt\")\n\nFind more information at https://github.com/tnozicka/openshift-acme",
		RunE: func(cmd *cobra.Command, args []string) error {
			defer klog.Flush()

			err := o.Validate()
			if err != nil {
				return err
			}

			err = o.Complete()
			if err != nil {
				return err
			}

			err = o.Run(cmd, streams)
			if err != nil {
				return err
			}

			return nil
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := cmdutil.ReadFlagsFromEnv("OPENSHIFT_ACME_CONTROLLER_", cmd)
			if err != nil {
				return err
			}

			return nil
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	rootCmd.PersistentFlags().StringVarP(&o.Kubeconfig, "kubeconfig", "", o.Kubeconfig, "Path to the kubeconfig file")
	rootCmd.PersistentFlags().StringVarP(&o.AcmeUrl, "acmeurl", "", o.AcmeUrl, "ACME URL like https://acme-v01.api.letsencrypt.org/directory")
	rootCmd.PersistentFlags().StringArrayVarP(&o.Namespaces, "namespace", "n", o.Namespaces, "Restricts controller to namespace(s). If not specified controller watches all namespaces.")
	rootCmd.PersistentFlags().StringVarP(&o.AcmeAccountSecret, "acme-account-secret", "", o.AcmeAccountSecret, "Name of the Secret holding ACME account.")

	cmdutil.InstallKlog(rootCmd)

	return rootCmd
}

func (o *Options) Validate() error {
	var errs []error

	for _, namespace := range o.Namespaces {
		errStrings := kvalidation.ValidateNamespaceName(namespace, false)
		if len(errStrings) > 0 {
			errs = append(errs, fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(errStrings, ", ")))
		}
	}
	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}

	if o.AcmeAccountSecret == "" {
		return fmt.Errorf("acme account secret name can't be empty string")
	}
	errStrings := kvalidation.NameIsDNSSubdomain(o.AcmeAccountSecret, false)
	if len(errs) > 0 {
		return fmt.Errorf("acme account secret name is invalid: %s", strings.Join(errStrings, ", "))
	}

	// TODO

	return nil
}

func (o *Options) Complete() error {
	var err error

	if len(o.Kubeconfig) != 0 {
		klog.V(1).Infof("Using kubeconfig %q.", o.Kubeconfig)
		o.restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: o.Kubeconfig}, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return fmt.Errorf("can't create config from kubeConfigPath %q: %v", o.Kubeconfig, err)
		}
	} else {
		klog.V(1).Infof("No kubeconfig specified, using InClusterConfig.")
		o.restConfig, err = restclient.InClusterConfig()
		if err != nil {
			klog.Fatalf("Failed to create InClusterConfig: %v", err)
		}
	}

	o.kubeClient, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return fmt.Errorf("can't build kubernetes clientset: %v", err)
	}

	o.routeClient, err = routeclientset.NewForConfig(o.restConfig)
	if err != nil {
		return fmt.Errorf("can't build route clientset: %v", err)
	}

	if len(o.Namespaces) == 0 {
		// empty namespace will lead to creating cluster wide informers
		o.Namespaces = []string{metav1.NamespaceAll}
	}

	return nil
}

func (o *Options) Run(cmd *cobra.Command, streams genericclioptions.IOStreams) error {
	stopCh := signals.StopChannel()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-stopCh
		cancel()
	}()

	klog.Infof("loglevel is set to %q", cmdutil.GetLoglevel())
	klog.Infof("Using ACME server URL %q", o.AcmeUrl)

	for _, namespace := range o.Namespaces {
		cache.NewIndexerInformer()
	}

	routeInformer := routeinformersv1.NewRouteInformer(routeClientset, namespace, ResyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	klog.Infof("Starting Route informer")
	go routeInformer.Run(stopCh)

	secretInformer := kcoreinformersv1.NewSecretInformer(kubeClientset, namespace, ResyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	klog.Infof("Starting Secret informer")
	go secretInformer.Run(stopCh)

	http01, err := challengeexposers.NewHttp01(ctx, listenAddr)
	if err != nil {
		return err
	}

	exposers := map[string]challengeexposers.Interface{
		"http-01": http01,
	}

	// Wait secretInformer to sync so we can create acmeClientFactory
	if !cache.WaitForCacheSync(stopCh, secretInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for secretInformer caches to sync")
	}
	secretLister := kcorelistersv1.NewSecretLister(secretInformer.GetIndexer())
	acmeClientFactory := acmeclientbuilder.NewSharedClientFactory(acmeUrl, accountName, selfNamespace, kubeClientset, secretLister)

	rc := routecontroller.NewRouteController(acmeClientFactory, exposers, routeClientset, kubeClientset, routeInformer, secretInformer, exposerIP, int32(exposerPort), selfNamespace, selfSelector, defaultRouteTermination)
	go rc.Run(Workers, stopCh)

	<-stopCh

	// TODO: We should wait for controllers to stop

	klog.Flush()

	return nil
}
