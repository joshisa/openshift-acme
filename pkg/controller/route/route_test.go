package route

import (
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/tnozicka/openshift-acme/pkg/api"
	"k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

func TestGetTemporaryName(t *testing.T) {
	tt := []struct {
		name string
		key  string
	}{
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "simple key",
			key:  "my_route",
		},
		{
			name: "combined key",
			key:  "my_route:a.com/b/c/42",
		},
		{
			name: "long key",
			key:  utilrand.String(utilvalidation.DNS1035LabelMaxLength * 2),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := getTemporaryName(tc.key)

			errs := validation.NameIsDNSSubdomain(r, false)
			if len(errs) != 0 {
				t.Errorf("name %q isn't DNS subdomain: %v", r, errs)
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tt := []struct {
		name        string
		status      api.Status
		obj         metav1.ObjectMeta
		expectedObj metav1.ObjectMeta
		expectedErr error
	}{
		{
			name: "Sets status if annotations are nil",
			status: api.Status{
				ObservedGeneration: 42,
				CertificateMeta: &api.CertificateMeta{
					NotBefore: time.Date(2020, 01, 31, 23, 59, 58, 1, time.UTC),
					NotAfter:  time.Date(2021, 01, 31, 23, 59, 58, 1, time.UTC),
					Domains:   []string{"k8s.io", "openshift.io"},
				},
				ProvisioningStatus: &api.CertProvisioningStatus{
					StartedAt:   time.Date(2020, 01, 31, 23, 59, 42, 1, time.UTC),
					OrderURI:    "http://localhost/",
					OrderStatus: "Invalids",
					OrderError: &api.OrderError{
						StatusCode:  503,
						ProblemType: "Service Unavailable",
						Detail:      "Server is down.",
					},
					AccountHash: "account-sha256",
				},
				Signature: "signature-sha256",
			},
			obj: metav1.ObjectMeta{
				Annotations: nil,
			},
			expectedObj: metav1.ObjectMeta{
				Annotations: map[string]string{},
			},
			expectedErr: nil,
		},
		{
			name: "Sets status and keep existing annotations",
			obj: metav1.ObjectMeta{
				Annotations: nil,
			},
			expectedErr: nil,
		},
		{
			name: "Sets status over existing status",
			obj: metav1.ObjectMeta{
				Annotations: nil,
			},
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := setStatus(&tc.obj, &tc.status)
			if !reflect.DeepEqual(err, tc.expectedErr) {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				return
			}

			if !reflect.DeepEqual(tc.obj, tc.expectedObj) {
				t.Error(spew.Sprintf("expected: %#v\ngot     : %#v\ndiff: %s", tc.expectedObj, tc.obj, cmp.Diff(tc.expectedObj, tc.obj)))
			}
		})
	}
}
