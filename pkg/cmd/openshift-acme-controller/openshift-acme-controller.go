package openshift_acme_controller

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	kvalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	routeclientset "github.com/openshift/client-go/route/clientset/versioned"

	acmeclientbuilder "github.com/tnozicka/openshift-acme/pkg/acme/client/builder"
	"github.com/tnozicka/openshift-acme/pkg/cmd/genericclioptions"
	cmdutil "github.com/tnozicka/openshift-acme/pkg/cmd/util"
	routecontroller "github.com/tnozicka/openshift-acme/pkg/controllers/route"
	kubeinformers "github.com/tnozicka/openshift-acme/pkg/machinery/informers/kube"
	routeinformers "github.com/tnozicka/openshift-acme/pkg/machinery/informers/route"
	"github.com/tnozicka/openshift-acme/pkg/signals"
)

type Options struct {
	genericclioptions.IOStreams

	Workers                     int
	Kubeconfig                  string
	ControllerNamespace         string
	LeaderelectionLeaseDuration time.Duration
	LeaderelectionRenewDeadline time.Duration
	LeaderelectionRetryPeriod   time.Duration
	Namespaces                  []string
	AcmeUrl                     string
	AcmeAccountSecret           string
	AcmeOrderTimeout            time.Duration

	restConfig  *restclient.Config
	kubeClient  kubernetes.Interface
	routeClient routeclientset.Interface
}

func NewOptions(streams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams:  streams,
		Workers:    10,
		Kubeconfig: "",

		LeaderelectionLeaseDuration: 15 * time.Second,
		LeaderelectionRenewDeadline: 10 * time.Second,
		LeaderelectionRetryPeriod:   2 * time.Second,

		AcmeUrl:           "https://acme-staging.api.letsencrypt.org/directory",
		AcmeAccountSecret: "acme-account",
		AcmeOrderTimeout:  5 * time.Minute,

		Namespaces: []string{metav1.NamespaceAll},
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

	rootCmd.PersistentFlags().IntVarP(&o.Workers, "workers", "", o.Workers, "Number of workers to run")
	rootCmd.PersistentFlags().StringVarP(&o.Kubeconfig, "kubeconfig", "", o.Kubeconfig, "Path to the kubeconfig file")
	rootCmd.PersistentFlags().StringVarP(&o.ControllerNamespace, "controller-namespace", "", o.ControllerNamespace, "Namespace where the controller is running. Autodetected if run inside a cluster.")
	rootCmd.PersistentFlags().StringArrayVarP(&o.Namespaces, "namespace", "n", o.Namespaces, "Restricts controller to namespace(s). If not specified controller watches all namespaces.")

	rootCmd.PersistentFlags().DurationVarP(&o.LeaderelectionLeaseDuration, "leaderelection-lease-duration", "LeaseDuration is the duration that non-leader candidates will wait to force acquire leadership.", o.LeaderelectionLeaseDuration, "")
	rootCmd.PersistentFlags().DurationVarP(&o.LeaderelectionRenewDeadline, "leaderelection-renew-deadline", "RenewDeadline is the duration that the acting master will retry refreshing leadership before giving up.", o.LeaderelectionRenewDeadline, "")
	rootCmd.PersistentFlags().DurationVarP(&o.LeaderelectionRetryPeriod, "leaderelection-retry-period", "RetryPeriod is the duration the LeaderElector clients should wait between tries of actions.", o.LeaderelectionRetryPeriod, "")

	rootCmd.PersistentFlags().StringVarP(&o.AcmeUrl, "acmeurl", "", o.AcmeUrl, "ACME URL like https://acme-v02.api.letsencrypt.org/directory")
	rootCmd.PersistentFlags().StringVarP(&o.AcmeAccountSecret, "acme-account-secret", "", o.AcmeAccountSecret, "Name of the Secret holding ACME account.")
	rootCmd.PersistentFlags().DurationVarP(&o.AcmeOrderTimeout, "acme-order-timeout", "", o.AcmeOrderTimeout, "Name of the Secret holding ACME account.")

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
			return fmt.Errorf("can't create InClusterConfig: %v", err)
		}
	}

	if len(o.ControllerNamespace) == 0 {
		// Autodetect if running inside a cluster
		bytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return fmt.Errorf("can't autodetect controller namespace: %v", err)
		}
		o.ControllerNamespace = string(bytes)
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

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	// add a uniquifier so that two processes on the same host don't accidentally both become active
	id := hostname + "_" + string(uuid.NewUUID())
	klog.V(4).Infof("Leaderelection ID is %q", id)

	// we use the Lease lock type since edits to Leases are less common
	// and fewer objects in the cluster watch "all Leases".
	lock := &resourcelock.ConfigMapLock{
		ConfigMapMeta: metav1.ObjectMeta{
			Name:      "acme-controller-locks",
			Namespace: o.ControllerNamespace,
		},
		Client: o.kubeClient.CoreV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	leChan := make(chan os.Signal, 2)

	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: o.LeaderelectionLeaseDuration,
		RenewDeadline: o.LeaderelectionRenewDeadline,
		RetryPeriod:   o.LeaderelectionRetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {

			},
			OnStoppedLeading: func() {
				klog.Fatalf("leaderelection lost")
			},
		},
		Name: "openshift-acme",
	})
	if err != nil {
		return fmt.Errorf("leaderelection failed: %v")
	}
	le.Run(ctx)

	select {
	case <-leChan:
		klog.Infof("Acquired leaderelection")
	case <-stopCh:
		return fmt.Errorf("interrupted before leaderelection")
	}

	klog.Infof("loglevel is set to %q", cmdutil.GetLoglevel())
	klog.Infof("Using ACME server URL %q", o.AcmeUrl)

	kubeInformersForNamespaces := kubeinformers.NewKubeInformersForNamespaces(o.kubeClient, o.Namespaces)
	routeInformersForNamespaces := routeinformers.NewRouteInformersForNamespaces(o.routeClient, o.Namespaces)

	acmeClientFactory := acmeclientbuilder.NewSharedClientFactory(o.AcmeUrl, o.AcmeAccountSecret, o.ControllerNamespace, o.kubeClient, kubeInformersForNamespaces.InformersFor(o.ControllerNamespace).Core().V1().Secrets().Lister())

	rc := routecontroller.NewRouteController(acmeClientFactory, o.kubeClient, kubeInformersForNamespaces, o.routeClient, routeInformersForNamespaces)

	kubeInformersForNamespaces.Start(stopCh)
	routeInformersForNamespaces.Start(stopCh)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rc.Run(o.Workers, stopCh)
	}()

	<-stopCh

	klog.Info("Waiting for controllers to finish...")
	wg.Wait()

	klog.Flush()

	return nil
}
