package controllers

import (
	"context"
	ibmv1alpha1 "github.com/IBM-Security/verify-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"time"
)

var _ = Describe("Verify Tenant controller", func() {

	const (
		VerifyTenatnName      = "verify-operator-test"
		VerifyTenantNamespace = "default"
		JobName               = "test-job"

		timeout  = time.Second * 30
		duration = time.Second * 30
		interval = time.Millisecond * 250
	)

	Context("When creating a tenant", func() {
		It("Should update the VerifyTenant Status.Version count when new VerifyTenant is created.", func() {
			By("By creating a new ibmv1alpha1.VerifyTenant")
			ctx := context.Background()

			key := types.NamespacedName{
				Name:      "verify-operator-test",
				Namespace: "default",
			}

			verifyTenant := &ibmv1alpha1.VerifyTenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: ibmv1alpha1.VerifyTenantSpec{
					SuperTenant:  "test.ibm.com",
					Tenant:       "verify-operator-test",
					Company:      "IBM",
					Contact:      "isamdev@au1.ibm.com",
					Version:      1,
					Secret:       "verify-tenant",
					Integration:  "CP4S",
					ClientId:     "ABCDabcd1234",
					ClientSecret: "ABCDabcd1234",
				},
			}

			//Create the resource
			Expect(k8sClient.Create(ctx, verifyTenant)).Should(Succeed())

			found := &ibmv1alpha1.VerifyTenant{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, key, found)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())
			Expect(found.Spec.Version).Should(Equal(1))

			updatedTenantSpec := &ibmv1alpha1.VerifyTenantSpec{
				SuperTenant:  "test.ibm.com",
				Tenant:       "verify-operator-test",
				Company:      "IBM",
				Contact:      "isamdev@au1.ibm.com",
				Version:      2,
				Secret:       "verify-tenant",
				Integration:  "CP4S",
				ClientId:     "ABCDabcd1234",
				ClientSecret: "ABCDabcd1234",
			}

			found.Spec = *updatedTenantSpec

			Expect(k8sClient.Update(context.Background(), found)).Should(Succeed())
			foundUpdated := &ibmv1alpha1.VerifyTenant{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, key, foundUpdated)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())
			Expect(foundUpdated.Spec.Version).Should(Equal(2))
		})
	})
})
