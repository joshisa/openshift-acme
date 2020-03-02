package api

import (
	"time"
)

const (
	DefaultTlsAcmeAnnotation = "kubernetes.io/tls-acme"

	AcmeStatusAnnotation   = "acme.openshift.io/status"
	AcmePriorityAnnotation = "acme.openshift.io/priority"
	AcmeTemporaryLabel     = "acme.openshift.io/temporary"
	AcmeExposerId          = "acme.openshift.io/exposer-id"
	AcmeExposerKey         = "acme.openshift.io/exposer-key"
	AcmeExposerUID         = "acme.openshift.io/exposer-uid"
	AcmeCertIssuerName     = "acme.openshift.io/cert-issuer-name"
)

type CertIssuerType string

const (
	CertIssuerDataKey                 = "cert-issuer.types.acme.openshift.io"
	CertIssuerTypeAcme CertIssuerType = "ACME"
)

type AcmeAccountStatus struct {
	Hash          string `json:"hash"`
	URI           string `json:"uri"`
	AccountStatus string `json:"accountStatus"`
	OrdersURL     string `json:"ordersURL"`
}
type AcmeAccount struct {
	Contacts []string `json:"contacts"`

	Status AcmeAccountStatus ` json:"status"`
}

type AcmeCertIssuer struct {
	DirectoryURL string      `json:"directoryURL"`
	Account      AcmeAccount `json:"account"`
}

type CertIssuer struct {
	SecretName string `json:"secretName"`

	Type           CertIssuerType  `json:"type"`
	AcmeCertIssuer *AcmeCertIssuer `json:"acmeCertIssuer"`
}

type CertificateMeta struct {
	//
	NotBefore time.Time `json:"notBefore"`

	//
	NotAfter time.Time `json:"notAfter"`

	//
	Domains []string `json:"domains"`
}

type OrderError struct {
	// statusCode is the HTTP status code generated by the origin server.
	StatusCode int `json:"statusCode,omitempty"`

	// problemType is a URI reference that identifies the problem type,
	// typically in a "urn:acme:error:xxx" form.
	ProblemType string `json:"problemType,omitempty"`

	// detail is a human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail,omitempty"`
}

type CertProvisioningStatus struct {
	// startedAt marks the time when the provisioning process begun.
	StartedAt time.Time `json:"startedAt,omitempty"`

	// EarliestAttemptAt marks the earliest time the provisioning process can be retried.
	EarliestAttemptAt time.Time `json:"earliestAttemptAt,omitempty"`

	// startedAt marks the time when the provisioning process begun.
	Failures int `json:"failures,omitempty"`

	// orderUri, if not empty, holds the URI for active certificate order.
	OrderURI string `json:"orderURI,omitempty"`

	// orderStatus hold the status of the active order.
	OrderStatus string `json:"orderStatus,omitempty"`

	// orderError hold the details if the order failed
	OrderError *OrderError `json:"orderError,omitempty"`

	// accountHash holds the internal identification on the account.
	AccountHash string `json:"accountHash,omitempty"`
}

// Status represents the current state of certificates provisioning.
type Status struct {
	// observedGeneration is the most recent generation observed by the controller. It corresponds to the
	// object's generation, which is updated on mutation by the API Server.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// certificateMeta
	CertificateMeta *CertificateMeta `json:"certificateMeta,omitempty"`

	// provisioningStatus
	ProvisioningStatus CertProvisioningStatus `json:"provisioningStatus"`

	// signature (internal) holds the cryptographic signature controller uses for internal check
	// that prevents messing with status filed and injection e.g. malicious URLs.
	Signature string `json:"signature,omitempty"`
}
