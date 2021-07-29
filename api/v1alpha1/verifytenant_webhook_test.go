package v1alpha1

import (
	"context"
	. "github.com/onsi/ginkgo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"time"
)

var _ = Describe("Verify Tenant Webhook", func() {

	const (
		VerifyTenantName      = "verify-operator-test"
		VerifyTenantNamespace = "default"
		JobName               = "test-job"

		timeout  = time.Second * 30
		duration = time.Second * 30
		interval = time.Millisecond * 250
	)

	Context("Validating Webhook for VerifyTenant CRD", func() {
		It("Should validate fields and throw an error if invalid.", func() {
			By("By invoking the validating webhook")
			ctx := context.Background()

			key := types.NamespacedName{
				Name:      "verify-operator-test",
				Namespace: "default",
			}

			tests := []struct {
				tenant        string
				super_tenant  string
				company       string
				contact       string
				version       int
				secret        string
				namespaces    []string
				integration   string
				client_id     string
				client_secret string
				error_string  string
			}{
				{"http://invalid.super.tenant", "tenant", "MBI", "a@b.c", 1, "secret", []string{"default"}, "CP4S", "abcdABCD134", "abcdABCD1234", "TODO"},
				{"super.tenant", "invalid/tenant", "IBM", "a@b.c", 1, "secret", []string{"default"}, "CP4S", "string", "string", "TODO"},
				{"super.tenant", "tenant", "IBM", "invalid.email", 1, "secret", []string{"default"}, "CP4S", "string", "string", "TODO"},
				{"super.tenant", "tenant", "IBM", "a@b.c", -1, "secret", []string{"default"}, "CP4S", "string", "string", "TODO"},
			}
			for _, test := range tests {
				defer func() {
					if r := recover(); r != nil {
						var ok bool
						err, ok := r.(error)
						if !ok && err.Error() != test.error_string {
							panic(err.Error())
						}
					}
				}()
				verifyTenant := &VerifyTenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      key.Name,
						Namespace: key.Namespace,
					},
					Spec: VerifyTenantSpec{
						SuperTenant:  test.super_tenant,
						Tenant:       test.tenant,
						Company:      test.company,
						Contact:      test.contact,
						Version:      test.version,
						Secret:       test.secret,
						Namespaces:   test.namespaces,
						Integration:  test.integration,
						ClientId:     test.client_id,
						ClientSecret: test.client_secret,
					},
				}
				k8sClient.Create(ctx, verifyTenant)
			}
		})
	})
})
