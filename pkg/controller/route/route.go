package route

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghodss/yaml"
	"golang.org/x/crypto/acme"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	routev1 "github.com/openshift/api/route/v1"
	routeclientset "github.com/openshift/client-go/route/clientset/versioned"
	_ "github.com/openshift/client-go/route/clientset/versioned/scheme"
	"github.com/tnozicka/openshift-acme/pkg/api"
	"github.com/tnozicka/openshift-acme/pkg/cert"
	"github.com/tnozicka/openshift-acme/pkg/helpers"
	kubeinformers "github.com/tnozicka/openshift-acme/pkg/machinery/informers/kube"
	routeinformers "github.com/tnozicka/openshift-acme/pkg/machinery/informers/route"
	routeutil "github.com/tnozicka/openshift-acme/pkg/route"
	"github.com/tnozicka/openshift-acme/pkg/util"
)

const (
	ControllerName = "openshift-acme-controller"
	ExposerFileKey = "exposer-file"
	// Remove this when we have separate rate limiting for ACME.
	// Now it will get eventually reconciled when informers re-sync or on edit.
	MaxRetries               = 50 // 2
	RenewalStandardDeviation = 1
	RenewalMean              = 0
	AcmeTimeout              = 60 * time.Second
)

var (
	KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
	// controllerKind contains the schema.GroupVersionKind for this controller type.
	controllerKind = routev1.SchemeGroupVersion.WithKind("Route")
)

type RouteController struct {
	orderTimeout time.Duration
	exposerImage string

	kubeClient                 kubernetes.Interface
	kubeInformersForNamespaces kubeinformers.Interface

	// appsClient                 kubernetes.Interface
	// appsInformersForNamespaces kubeinformers.Interface

	routeClient                 routeclientset.Interface
	routeInformersForNamespaces routeinformers.Interface

	cachesToSync []cache.InformerSynced

	recorder record.EventRecorder

	queue workqueue.RateLimitingInterface
}

func NewRouteController(
	orderTimeout time.Duration,
	exposerImage string,
	kubeClient kubernetes.Interface,
	kubeInformersForNamespaces kubeinformers.Interface,
	routeClient routeclientset.Interface,
	routeInformersForNamespaces routeinformers.Interface,
) *RouteController {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	rc := &RouteController{
		orderTimeout: orderTimeout,
		exposerImage: exposerImage,

		kubeClient:                 kubeClient,
		kubeInformersForNamespaces: kubeInformersForNamespaces,

		routeClient:                 routeClient,
		routeInformersForNamespaces: routeInformersForNamespaces,

		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: ControllerName}),

		queue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	if len(routeInformersForNamespaces.Namespaces()) < 1 {
		panic("no namespace set up")
	}

	for _, namespace := range routeInformersForNamespaces.Namespaces() {
		klog.V(4).Infof("Setting up route informers for namespace %q", namespace)

		informers := routeInformersForNamespaces.InformersFor(namespace)

		informers.Route().V1().Routes().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    rc.addRoute,
			UpdateFunc: rc.updateRoute,
			DeleteFunc: rc.deleteRoute,
		})
		rc.cachesToSync = append(rc.cachesToSync, informers.Route().V1().Routes().Informer().HasSynced)
	}

	if len(kubeInformersForNamespaces.Namespaces()) < 1 {
		panic("no namespace set up")
	}

	for _, namespace := range kubeInformersForNamespaces.Namespaces() {
		klog.V(4).Infof("Setting up kube informers for namespace %q", namespace)

		informers := kubeInformersForNamespaces.InformersFor(namespace)

		informers.Core().V1().Secrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: rc.updateSecret,
			DeleteFunc: rc.deleteSecret,
		})
		rc.cachesToSync = append(rc.cachesToSync, informers.Core().V1().Secrets().Informer().HasSynced)
	}

	return rc
}

func (rc *RouteController) enqueueRoute(route *routev1.Route) {
	key, err := KeyFunc(route)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for route object: %w", err))
		return
	}

	rc.queue.Add(key)
}

func (rc *RouteController) addRoute(obj interface{}) {
	route := obj.(*routev1.Route)
	if !util.IsManaged(route) {
		klog.V(5).Infof("Skipping Route %s/%s UID=%s RV=%s", route.Namespace, route.Name, route.UID, route.ResourceVersion)
		return
	}

	klog.V(4).Infof("Adding Route %s/%s UID=%s RV=%s; %#v", route.Namespace, route.Name, route.UID, route.ResourceVersion, route)
	rc.enqueueRoute(route)
}

func (rc *RouteController) updateRoute(old, cur interface{}) {
	oldRoute := old.(*routev1.Route)
	newRoute := cur.(*routev1.Route)

	if !util.IsManaged(newRoute) {
		klog.V(5).Infof("Skipping Route %s/%s UID=%s RV=%s", newRoute.Namespace, newRoute.Name, newRoute.UID, newRoute.ResourceVersion)
		return
	}

	klog.V(4).Infof("Updating Route from %s/%s UID=%s RV=%s to %s/%s UID=%s,RV=%s",
		oldRoute.Namespace, oldRoute.Name, oldRoute.UID, oldRoute.ResourceVersion,
		newRoute.Namespace, newRoute.Name, newRoute.UID, newRoute.ResourceVersion)

	rc.enqueueRoute(newRoute)
}

func (rc *RouteController) deleteRoute(obj interface{}) {
	route, ok := obj.(*routev1.Route)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("object is not a Route neither tombstone: %#v", obj))
			return
		}
		route, ok = tombstone.Obj.(*routev1.Route)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Route %#v", obj))
			return
		}
	}

	if !util.IsManaged(route) {
		klog.V(5).Infof("Skipping Route %s/%s UID=%s RV=%s", route.Namespace, route.Name, route.UID, route.ResourceVersion)
		return
	}

	klog.V(4).Infof("Deleting Route %s/%s UID=%s RV=%s", route.Namespace, route.Name, route.UID, route.ResourceVersion)
	rc.enqueueRoute(route)
}

func (rc *RouteController) updateSecret(old, cur interface{}) {
	oldSecret := old.(*corev1.Secret)
	curSecret := cur.(*corev1.Secret)

	// Ignore periodic re-lists for Secrets.
	if oldSecret.ResourceVersion == curSecret.ResourceVersion {
		return
	}

	curControllerRef := metav1.GetControllerOf(curSecret)

	// If it has a ControllerRef, that's all that matters.
	if curControllerRef != nil {
		route := rc.resolveControllerRef(curSecret.Namespace, curControllerRef)
		if route == nil {
			return
		}
		klog.V(4).Infof("Acme Secret %s/%s updated.", curSecret.Namespace, curSecret.Name)
		rc.enqueueRoute(route)
		return
	}
}

func (rc *RouteController) deleteSecret(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("object is not a Secret neither tombstone: %#v", obj))
			return
		}
		secret, ok = tombstone.Obj.(*corev1.Secret)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Secret: %#v", obj))
			return
		}
	}

	controllerRef := metav1.GetControllerOf(secret)
	if controllerRef == nil {
		return
	}
	route := rc.resolveControllerRef(secret.Namespace, controllerRef)
	if route == nil {
		return
	}

	klog.V(4).Infof("Secret %s/%s deleted.", secret.Namespace, secret.Name)
	rc.enqueueRoute(route)
}

// resolveControllerRef returns the controller referenced by a ControllerRef,
// or nil if the ControllerRef could not be resolved to a matching controller
// of the correct Kind.
func (rc *RouteController) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *routev1.Route {
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}

	route, err := rc.routeInformersForNamespaces.InformersForOrGlobal(namespace).Route().V1().Routes().Lister().Routes(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}

	if route.UID != controllerRef.UID {
		return nil
	}

	return route
}

func needsCertKey(t time.Time, route *routev1.Route) (string, error) {
	if route.Spec.TLS == nil || route.Spec.TLS.Key == "" || route.Spec.TLS.Certificate == "" {
		return "Route is missing CertKey", nil
	}

	certPemData := &cert.CertPemData{
		Key: []byte(route.Spec.TLS.Key),
		Crt: []byte(route.Spec.TLS.Certificate),
	}
	certificate, err := certPemData.Certificate()
	if err != nil {
		return "", fmt.Errorf("can't decode certificate from Route %s/%s: %v", route.Namespace, route.Name, err)
	}

	err = certificate.VerifyHostname(route.Spec.Host)
	if err != nil {
		return "", fmt.Errorf("route %s/%s: existing certificate doesn't match hostname %q", route.Namespace, route.Name, route.Spec.Host)
	}

	if !cert.IsValid(certificate, t) {
		return "Already expired", nil
	}

	// We need to trigger renewals before the certs expire
	remains := certificate.NotAfter.Sub(t)
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)

	// This is the deadline when we start renewing
	if remains <= lifetime/3 {
		return "In renewal period", nil
	}

	// In case many certificates were provisioned at specific time
	// We will try to avoid spikes by renewing randomly
	if remains <= lifetime/2 {
		// We need to randomize renewals to spread the load.
		// Closer to deadline, bigger chance
		s := rand.NewSource(t.UnixNano())
		r := rand.New(s)
		n := r.NormFloat64()*RenewalStandardDeviation + RenewalMean
		// We use left half of normal distribution (all negative numbers).
		if n < 0 {
			return "Proactive renewal", nil
		}
	}

	return "", nil
}

func (rc *RouteController) getStatus(routeReadOnly *routev1.Route) (*api.Status, error) {
	status := &api.Status{}
	if routeReadOnly.Annotations != nil {
		statusString := routeReadOnly.Annotations[api.AcmeStatusAnnotation]
		err := yaml.Unmarshal([]byte(statusString), status)
		if err != nil {
			return nil, fmt.Errorf("can't decode status annotation: %v", err)
		}
	}

	// TODO: verify it matches account hash

	// TODO: verify status signature

	return status, nil
}

func (rc *RouteController) setStatus(route *routev1.Route, status *api.Status) error {
	status.ObservedGeneration = route.Generation

	// TODO: sign the status

	bytes, err := yaml.Marshal(status)
	if err != nil {
		return fmt.Errorf("can't encode status annotation: %v", err)
	}

	metav1.SetMetaDataAnnotation(&route.ObjectMeta, api.AcmeStatusAnnotation, string(bytes))

	return nil
}

func (rc *RouteController) updateStatus(route *routev1.Route, status *api.Status) error {
	oldRoute := route.DeepCopy()

	err := rc.setStatus(route, status)
	if err != nil {
		return fmt.Errorf("can't set status: %v", err)
	}

	if reflect.DeepEqual(route, oldRoute) {
		return nil
	}

	_, err = rc.routeClient.RouteV1().Routes(route.Namespace).Update(route)
	if err != nil {
		return fmt.Errorf("can't update status: %v", err)
	}

	return nil
}

func (rc *RouteController) sync(ctx context.Context, key string) error {
	klog.V(4).Infof("Started syncing Route %q", key)
	defer func() {
		klog.V(4).Infof("Finished syncing Route %q", key)
	}()

	namespace, _, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(err)
		return err
	}

	objReadOnly, exists, err := rc.routeInformersForNamespaces.InformersForOrGlobal(namespace).Route().V1().Routes().Informer().GetIndexer().GetByKey(key)
	if err != nil {
		klog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		klog.V(4).Infof("Route %s does not exist anymore\n", key)
		return nil
	}

	routeReadOnly := objReadOnly.(*routev1.Route)

	// Don't act on objects that are being deleted.
	if routeReadOnly.DeletionTimestamp != nil {
		return nil
	}

	// Although we check when adding the Route into the queue it might have been waiting for a while and edited
	if !util.IsManaged(routeReadOnly) {
		klog.V(4).Infof("Skipping Route %s/%s UID=%s RV=%s", routeReadOnly.Namespace, routeReadOnly.Name, routeReadOnly.UID, routeReadOnly.ResourceVersion)
		return nil
	}

	// We have to check if Route is admitted to be sure it owns the domain!
	if !routeutil.IsAdmitted(routeReadOnly) {
		klog.V(4).Infof("Skipping Route %s because it's not admitted", key)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), AcmeTimeout)
	defer cancel()

	issuerConfigMaps, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Core().V1().ConfigMaps().Lister().ConfigMaps(routeReadOnly.Namespace).List(api.AccountLabelSet.AsSelector())
	if err != nil {
		return err
	}

	if len(issuerConfigMaps) < 1 {
		return fmt.Errorf("can't find any issuer")
	}

	// TODO: Filter out non-matching issuers and solvers

	if len(issuerConfigMaps) < 1 {
		return fmt.Errorf("no issuer matched the requirements")
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

	certIssuerCM := issuerConfigMaps[0]

	certIssuerData, ok := certIssuerCM.Data[api.CertIssuerDataKey]
	if !ok {
		return fmt.Errorf("configmap %s is matching CertIssuer selectors %q but missing key %q", key, api.AccountLabelSet, api.CertIssuerDataKey)
	}

	certIssuer := &api.CertIssuer{}
	err = yaml.Unmarshal([]byte(certIssuerData), certIssuer)
	if err != nil {
		return fmt.Errorf("configmap %s is matching CertIssuer selectors %q but contains invalid object: %w", key, api.AccountLabelSet, err)
	}

	switch certIssuer.Type {
	case api.CertIssuerTypeAcme:
		break
	default:
		return fmt.Errorf("unsupported cert issuer type %q", certIssuer.Type)
	}

	acmeIssuer := certIssuer.AcmeCertIssuer
	if acmeIssuer == nil {
		return fmt.Errorf("ACME issuer is missing AcmeCertIssuer spec")
	}

	secret, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(certIssuerCM.Namespace).Core().V1().Secrets().Lister().Secrets(certIssuerCM.Namespace).Get(acmeIssuer.AccountCredentialsSecretName)
	if err != nil {
		return err
	}

	acmeClient := &acme.Client{
		DirectoryURL: acmeIssuer.DirectoryUrl,
		UserAgent:    "github.com/tnozicka/openshift-acme",
	}

	acmeClient.Key, err = helpers.PrivateKeyFromSecret(secret)
	if err != nil {
		return err
	}

	status, err := rc.getStatus(routeReadOnly)
	if err != nil {
		return fmt.Errorf("can't get status: %v", err)
	}

	if status.ProvisioningStatus == nil {
		reason, err := needsCertKey(time.Now(), routeReadOnly)
		if err != nil {
			return err
		}

		if len(reason) == 0 {
			// Not eligible for renewal
			klog.V(4).Infof("Route %q doesn't need new certificate", key)
			return rc.updateStatus(routeReadOnly.DeepCopy(), status)
		}

		klog.V(1).Infof("Route %q needs new certificate: %v", key, reason)
	}

	domain := routeReadOnly.Spec.Host

	if status.ProvisioningStatus == nil {
		status.ProvisioningStatus = &api.CertProvisioningStatus{}
	}
	if len(status.ProvisioningStatus.OrderUri) == 0 {
		order, err := acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(domain))
		if err != nil {
			return err
		}
		klog.V(1).Infof("Created Order %q for Route %q", order.URI, key)

		// We need to store the order URI immediately to prevent loosing it on error.
		// Updating the route will make it requeue.
		status.ProvisioningStatus.StartedAt = time.Now()
		status.ProvisioningStatus.OrderUri = order.URI
		return rc.updateStatus(routeReadOnly.DeepCopy(), status)
	}

	// Clear stuck provisioning
	if time.Now().After(status.ProvisioningStatus.StartedAt.Add(rc.orderTimeout)) {
		klog.Warningf("Route %q: Clearing stuck order %q", key, status.ProvisioningStatus.OrderUri)
		status.ProvisioningStatus = nil
		return rc.updateStatus(routeReadOnly.DeepCopy(), status)
	}

	order, err := acmeClient.GetOrder(ctx, status.ProvisioningStatus.OrderUri)
	if err != nil {
		acmeErr, ok := err.(*acme.Error)
		if !ok || acmeErr.StatusCode != http.StatusNotFound {
			return err
		}

		// The order URI doesn't exist. Delete OrderUri and update the status.
		klog.Warningf("Route %q: Found invalid OrderURI %q, removing it.", key, status.ProvisioningStatus.OrderUri)
		status.ProvisioningStatus.OrderUri = ""
		return rc.updateStatus(routeReadOnly.DeepCopy(), status)
	}
	// TODO: acme or golang should fill in the value
	order.URI = status.ProvisioningStatus.OrderUri

	status.ProvisioningStatus.OrderStatus = order.Status

	klog.V(4).Infof("Route %q: Order %q is in %q state", key, order.URI, order.Status)

	switch order.Status {
	case acme.StatusPending:
		// Satisfy all pending authorizations.
		klog.V(4).Infof("Route %q: Order %q contains %d authorization(s)", key, order.URI, len(order.AuthzURLs))

		for _, authzUrl := range order.AuthzURLs {
			authz, err := acmeClient.GetAuthorization(ctx, authzUrl)
			if err != nil {
				return err
			}

			klog.V(4).Infof("Route %q: order %q: authz %q: is in %q state", key, order.URI, authz.URI, authz.Status)

			switch authz.Status {
			case acme.StatusPending:
				break

			case acme.StatusValid, acme.StatusInvalid, acme.StatusDeactivated, acme.StatusExpired, acme.StatusRevoked:
				continue

			default:
				return fmt.Errorf("route %q: order %q: authz %q has invalid status %q", key, order.URI, authz.URI, authz.Status)
			}

			// Authz is Pending

			var challenge *acme.Challenge
			for _, c := range authz.Challenges {
				if c.Type == "http-01" {
					challenge = c
				}
			}

			if challenge == nil {
				// TODO: emit an event
				return fmt.Errorf("route %q: unable to satisfy authorization %q for domain %q: no viable challenge type found in %v", key, authz.URI, domain, authz.Challenges)
			}

			klog.V(4).Infof("route %q: order %q: authz %q: challenge %q is in %q state", key, order.URI, authz.URI, authz.Status, challenge.Status)

			switch challenge.Status {
			case acme.StatusPending:
				id := routeReadOnly.Name + ":" + order.URI + ":" + authzUrl + ":" + challenge.URI
				tmpName := getTemporaryName(id)
				klog.Infof("id: %q, tmpName: %q", id, tmpName)

				challengePath := acmeClient.HTTP01ChallengePath(challenge.Token)
				challengeResponse, err := acmeClient.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return err
				}

				/*
				 * Route
				 */
				trueVal := true
				desiredExposerRoute := routeReadOnly.DeepCopy()
				desiredExposerRoute.Name = tmpName
				desiredExposerRoute.ResourceVersion = ""
				desiredExposerRoute.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: routev1.SchemeGroupVersion.String(),
						Kind:       "Route",
						Name:       routeReadOnly.Name,
						UID:        routeReadOnly.UID,
						Controller: &trueVal,
					},
				}
				if desiredExposerRoute.Annotations == nil {
					desiredExposerRoute.Annotations = map[string]string{}
				}
				desiredExposerRoute.Annotations[api.AcmeExposerId] = id
				if desiredExposerRoute.Labels == nil {
					desiredExposerRoute.Labels = map[string]string{}
				}
				desiredExposerRoute.Labels[api.AcmeTemporaryLabel] = "true"
				desiredExposerRoute.Spec.Path = acmeClient.HTTP01ChallengePath(challenge.Token)
				desiredExposerRoute.Spec.To = routev1.RouteTargetReference{
					Kind: "Service",
					Name: tmpName,
				}

				exposerRoute, err := rc.routeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Route().V1().Routes().Lister().Routes(routeReadOnly.Namespace).Get(desiredExposerRoute.Name)
				if err != nil {
					if kapierrors.IsNotFound(err) {
						exposerRoute, err = rc.routeClient.RouteV1().Routes(routeReadOnly.Namespace).Create(desiredExposerRoute)
						if err != nil {
							return err
						}
					}
				}

				if !metav1.IsControlledBy(exposerRoute, routeReadOnly) {
					return fmt.Errorf("exposer Route %s/%s already exists and isn't owned by route %s", exposerRoute.Namespace, exposerRoute.Name, key)
				}

				// Check the id to avoid collisions
				exposerRouteId, ok := desiredExposerRoute.Annotations[api.AcmeExposerId]
				if !ok {
					return fmt.Errorf("exposer route %s/%s misses exposer id", exposerRoute.Namespace, exposerRoute.Name)
				} else if exposerRouteId != id {
					return fmt.Errorf("exposer route %s/%s id missmatch: expected %q, got %q", exposerRoute.Namespace, exposerRoute.Name, id, exposerRouteId)
				}

				ownerRefToExposerRoute := metav1.OwnerReference{
					APIVersion: corev1.SchemeGroupVersion.String(),
					Kind:       "Route",
					Name:       exposerRoute.Name,
					UID:        exposerRoute.UID,
					Controller: &trueVal,
				}

				/*
				 * Secret
				 */
				desiredExposerSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            tmpName,
						OwnerReferences: []metav1.OwnerReference{ownerRefToExposerRoute},
						Annotations: map[string]string{
							api.AcmeExposerId: id,
						},
						Labels: map[string]string{
							api.AcmeTemporaryLabel: "true",
						},
					},
					StringData: map[string]string{
						ExposerFileKey: challengePath + "" + challengeResponse,
					},
				}
				exposerSecret, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Core().V1().Secrets().Lister().Secrets(routeReadOnly.Namespace).Get(desiredExposerSecret.Name)
				if err != nil {
					if kapierrors.IsNotFound(err) {
						exposerSecret, err = rc.kubeClient.CoreV1().Secrets(routeReadOnly.Namespace).Create(desiredExposerSecret)
						if err != nil {
							return err
						}
					}
				}

				if !metav1.IsControlledBy(exposerSecret, exposerRoute) {
					return fmt.Errorf("secret %s/%s already exists and isn't owned by expúoser route %s/%s", exposerSecret.Namespace, exposerSecret.Name, exposerRoute.Namespace, exposerRoute.Name)
				}

				// Check the id to avoid collisions
				exposerSecretId, ok := desiredExposerRoute.Annotations[api.AcmeExposerId]
				if !ok {
					return fmt.Errorf("exposer secret %s/%s misses exposer id", exposerRoute.Namespace, exposerRoute.Name)
				} else if exposerSecretId != id {
					return fmt.Errorf("exposer secret %s/%s id missmatch: expected %q, got %q", exposerRoute.Namespace, exposerRoute.Name, id, exposerSecretId)
				}

				/*
				 * ReplicaSet
				 */
				var replicas int32 = 2
				podLabels := map[string]string{
					"app": tmpName,
				}
				podSelector := &metav1.LabelSelector{
					MatchLabels: podLabels,
				}
				desiredExposerRS := &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:            tmpName,
						OwnerReferences: []metav1.OwnerReference{ownerRefToExposerRoute},
						Annotations: map[string]string{
							api.AcmeExposerId: id,
						},
						Labels: map[string]string{
							api.AcmeTemporaryLabel: "true",
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Replicas: &replicas,
						Selector: podSelector,
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: podLabels,
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "exposer",
										Image: rc.exposerImage,
										Command: []string{
											"openshift-acme-exposer",
										},
										Args: []string{
											"--response-file=/etc/openshift-acme-exposer/response-file",
										},
										VolumeMounts: []corev1.VolumeMount{
											{
												Name:      "exposerData",
												ReadOnly:  true,
												MountPath: "/etc/openshift-acme-exposer/response-file",
											},
										},
									},
								},
								Volumes: []corev1.Volume{
									{
										Name: "exposerData",
										VolumeSource: corev1.VolumeSource{
											Secret: &corev1.SecretVolumeSource{
												SecretName: exposerSecret.Name,
											},
										},
									},
								},
							},
						},
					},
				}
				exposerRS, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Apps().V1().ReplicaSets().Lister().ReplicaSets(routeReadOnly.Namespace).Get(desiredExposerRS.Name)
				if err != nil {
					if kapierrors.IsNotFound(err) {
						exposerRS, err = rc.kubeClient.AppsV1().ReplicaSets(routeReadOnly.Namespace).Create(desiredExposerRS)
						if err != nil {
							return err
						}
					}
				}

				if !metav1.IsControlledBy(exposerRS, exposerRoute) {
					return fmt.Errorf("RS %s/%s already exists and isn't owned by exposer route %s/%s", exposerRS.Namespace, exposerRS.Name, exposerRoute.Namespace, exposerRoute.Name)
				}

				// Check the id to avoid collisions
				exposerRSId, ok := desiredExposerRoute.Annotations[api.AcmeExposerId]
				if !ok {
					return fmt.Errorf("exposer RS %s/%s misses exposer id", exposerRoute.Namespace, exposerRoute.Name)
				} else if exposerRSId != id {
					return fmt.Errorf("exposer RS %s/%s id missmatch: expected %q, got %q", exposerRoute.Namespace, exposerRoute.Name, id, exposerRSId)
				}

				/*
				 * Service
				 */
				desiredExposerService := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:            tmpName,
						OwnerReferences: []metav1.OwnerReference{ownerRefToExposerRoute},
						Annotations: map[string]string{
							api.AcmeExposerId: id,
						},
						Labels: map[string]string{
							api.AcmeTemporaryLabel: "true",
						},
					},
					Spec: corev1.ServiceSpec{
						Selector: podLabels,
						Type:     corev1.ServiceTypeClusterIP,
					},
				}
				exposerService, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Core().V1().Services().Lister().Services(routeReadOnly.Namespace).Get(desiredExposerService.Name)
				if err != nil {
					if kapierrors.IsNotFound(err) {
						exposerService, err = rc.kubeClient.CoreV1().Services(routeReadOnly.Namespace).Create(desiredExposerService)
						if err != nil {
							return err
						}
					}
				}

				if !metav1.IsControlledBy(exposerService, routeReadOnly) {
					return fmt.Errorf("service %s/%s already exists and isn't owned by route %s", exposerService.Namespace, exposerService.Name, key)
				}

				// Check the id to avoid collisions
				exposerServiceId, ok := desiredExposerRoute.Annotations[api.AcmeExposerId]
				if !ok {
					return fmt.Errorf("exposer service %s/%s misses exposer id", exposerRoute.Namespace, exposerRoute.Name)
				} else if exposerServiceId != id {
					return fmt.Errorf("exposer service %s/%s id missmatch: expected %q, got %q", exposerRoute.Namespace, exposerRoute.Name, id, exposerServiceId)
				}

				// TODO: wait for pods to run and report into status, requeue
				// For now, the server is bound to retry the verification by RFC8555
				// so on happy path there shouldn't be issues. But pods can get stuck
				// on scheduling, quota, resources, ... and we want to know why the validation fails.

				_, err = acmeClient.Accept(ctx, challenge)
				if err != nil {
					return err
				}

			case acme.StatusProcessing, acme.StatusValid, acme.StatusInvalid:
				// These states will manifest into global order state over time.
				// We only need to attend to pending states.
				// We could possibly report events for those but is seems too fine grained for now.
				continue

			default:
				return fmt.Errorf("route %q: order %q: authz %q: invalid status %q for challenge %q", key, order.URI, authz.URI, challenge.Status, challenge.URI)
			}
		}

		return rc.updateStatus(routeReadOnly.DeepCopy(), status)

	case acme.StatusValid:
		// FIXME: should be separate step after acme.StatusReady - needs fixing golang acme lib
		fallthrough
	case acme.StatusReady:
		klog.V(3).Infof("Route %q: Order %q successfully validated", key, order.URI)
		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: routeReadOnly.Spec.Host,
			},
		}
		template.DNSNames = append(template.DNSNames, routeReadOnly.Spec.Host)
		klog.V(4).Infof("Route %q: Order %q: CSR template: %#v", key, order, template)
		privateKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %v", err)
		}

		csr, err := x509.CreateCertificateRequest(cryptorand.Reader, &template, privateKey)
		if err != nil {
			return fmt.Errorf("failed to create certificate request: %v", err)
		}
		klog.V(4).Infof("Route %q: Order %q: CSR: %#v", key, order.URI, string(csr))

		// Send CSR
		// FIXME: Unfortunately golang also waits in this method for the cert creation
		//  although that should be asynchronous. Requires fixing golang lib. (The helpers used are private.)
		der, certUrl, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil {
			return err
		}

		klog.V(4).Infof("Route %q: Order %q: Certificate available at %q", key, order.URI, certUrl)

		certPemData, err := cert.NewCertificateFromDER(der, privateKey)
		if err != nil {
			return fmt.Errorf("can't convert certificate from DER to PEM: %v", err)
		}

		route := routeReadOnly.DeepCopy()
		if route.Spec.TLS == nil {
			route.Spec.TLS = &routev1.TLSConfig{
				// Defaults
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
				Termination:                   routev1.TLSTerminationEdge,
			}
		}
		route.Spec.TLS.Key = string(certPemData.Key)
		route.Spec.TLS.Certificate = string(certPemData.Crt)

		_, err = rc.routeClient.RouteV1().Routes(routeReadOnly.Namespace).Update(route)
		if err != nil {
			return fmt.Errorf("can't update route %s/%s with new certificates: %v", routeReadOnly.Namespace, route.Name, err)
		}

		status.ProvisioningStatus = nil

		return rc.updateStatus(routeReadOnly.DeepCopy(), status)

	case acme.StatusProcessing:
		// TODO: backoff but capped at some reasonable time
		rc.queue.AddAfter(routeReadOnly, 15*time.Second)

		klog.V(4).Infof("Route %q: Order %q: Waiting to be validated by ACME server", key, order)

		return rc.updateStatus(routeReadOnly.DeepCopy(), status)

	case acme.StatusInvalid:
		var err error
		if order.Error != nil {
			err = order.Error
		} else {
			err = fmt.Errorf("order is missing an error")
		}
		rc.recorder.Eventf(routeReadOnly, corev1.EventTypeWarning, "AcmeFailedOrder", "Order %q for domain %q failed: %v", routeReadOnly.Spec.Host, err)

		return rc.updateStatus(routeReadOnly.DeepCopy(), status)

	default:
		return fmt.Errorf("route %q: invalid new order status %q; order URL: %q", key, order.Status, order.URI)
	}
}

// FIXME: move to its own sync loop
/*
func (rc *RouteController) syncSecret(routeReadOnly *routev1.Route) error {
	// TODO: consider option of choosing a oldSecret name using an annotation
	secretName := routeReadOnly.Name

	secretExists := true
	oldSecret, err := rc.kubeInformersForNamespaces.InformersForOrGlobal(routeReadOnly.Namespace).Core().V1().Secrets().Lister().Secrets(routeReadOnly.Namespace).Get(secretName)
	if err != nil {
		if !kapierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Secret %s/%s: %v", routeReadOnly.Namespace, secretName, err)
		}
		secretExists = false
	}

	// We need to make sure we can modify this oldSecret (has our controllerRef)
	if secretExists {
		controllerRef := GetControllerRef(&oldSecret.ObjectMeta)
		if controllerRef == nil || controllerRef.UID != routeReadOnly.UID {
			rc.recorder.Eventf(routeReadOnly, corev1.EventTypeWarning, "CollidingSecret", "Can't sync certificates for Route %s/%s into Secret %s/%s because it already exists and isn't owned by the Route!", routeReadOnly.Namespace, routeReadOnly.Name, routeReadOnly.Namespace, secretName)
			return nil
		}
	}

	if routeReadOnly.Spec.TLS == nil {
		if !secretExists {
			return nil
		}

		var gracePeriod int64 = 0
		propagationPolicy := metav1.DeletePropagationBackground
		preconditions := metav1.Preconditions{
			UID: &oldSecret.UID,
		}
		err := rc.kubeClient.CoreV1().Secrets(routeReadOnly.Namespace).Delete(secretName, &metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
			PropagationPolicy:  &propagationPolicy,
			Preconditions:      &preconditions,
		})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete oldSecret %s/%s: %s", routeReadOnly.Namespace, secretName, err)
			}
		}

		return nil
	}

	// Route has TLS; we need to sync it into a Secret
	var newSecret *corev1.Secret
	if secretExists {
		newSecret = oldSecret.DeepCopy()
	} else {
		newSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
		}
	}

	trueVal := true
	newSecret.ObjectMeta.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: controllerKind.GroupVersion().String(),
			Kind:       controllerKind.Kind,
			Name:       routeReadOnly.Name,
			UID:        routeReadOnly.UID,
			Controller: &trueVal,
		},
	}

	newSecret.Type = corev1.SecretTypeTLS

	if newSecret.Data == nil {
		newSecret.Data = make(map[string][]byte)
	}
	newSecret.Data[corev1.TLSCertKey] = []byte(routeReadOnly.Spec.TLS.Certificate)
	newSecret.Data[corev1.TLSPrivateKeyKey] = []byte(routeReadOnly.Spec.TLS.Key)

	if !secretExists {
		_, err = rc.kubeClient.CoreV1().Secrets(routeReadOnly.Namespace).Create(newSecret)
		if err != nil {
			return fmt.Errorf("failed to create Secret %s/%s with TLS data: %v", routeReadOnly.Namespace, newSecret.Name, err)
		}

		return nil
	}

	if !reflect.DeepEqual(oldSecret, newSecret) {
		_, err = rc.kubeClient.CoreV1().Secrets(routeReadOnly.Namespace).Update(newSecret)
		if err != nil {
			return fmt.Errorf("failed to update Secret %s/%s with TLS data: %v", routeReadOnly.Namespace, newSecret.Name, err)
		}
	}

	return nil
}
*/

// handleErr checks if an error happened and makes sure we will retry later.
func (rc *RouteController) handleErr(err error, key interface{}) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		rc.queue.Forget(key)
		return
	}

	if rc.queue.NumRequeues(key) < MaxRetries {
		klog.Infof("Error syncing Route %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		rc.queue.AddRateLimited(key)
		return
	}

	rc.queue.Forget(key)
	rc.queue.AddAfter(key, 24*time.Hour) // Try next day, until we have proper rate limiting for ACME requests
	// Report to an external entity that, even after several retries, we could not successfully process this key
	utilruntime.HandleError(err)
	klog.Infof("Dropping Route %q out of the queue: %v", key, err)
}

func (rc *RouteController) processNextItem(ctx context.Context) bool {
	// Wait until there is a new item in the working queue
	key, quit := rc.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two Routes with the same key are never processed in
	// parallel.
	defer rc.queue.Done(key)

	// Invoke the method containing the business logic
	err := rc.sync(ctx, key.(string))
	// Handle the error if something went wrong during the execution of the business logic
	rc.handleErr(err, key)
	return true
}

func (rc *RouteController) runWorker(ctx context.Context) {
	for rc.processNextItem(ctx) {
	}
}

func (rc *RouteController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	var wg sync.WaitGroup
	klog.Info("Starting Route controller")
	defer func() {
		klog.Info("Shutting down Route controller")
		rc.queue.ShutDown()
		wg.Wait()
		klog.Info("Route controller shut down")
	}()

	// Wait for all involved caches to be synced, before processing items from the queue is started
	synced := cache.WaitForNamedCacheSync("route controller", ctx.Done(), rc.cachesToSync...)
	if !synced {
		return
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wait.UntilWithContext(ctx, rc.runWorker, time.Second)
		}()
	}

	<-ctx.Done()
}

func getTemporaryName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("acme-exposer-%s", strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])))
}
