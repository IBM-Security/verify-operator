/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

import (
    "flag"
    "fmt"
    "io/ioutil"
    "os"

    // Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
    // to ensure that exec-entrypoint and run can make use of them.
    _ "k8s.io/client-go/plugin/pkg/client/auth"

    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"

    "sigs.k8s.io/controller-runtime/pkg/healthz"
    "sigs.k8s.io/controller-runtime/pkg/log/zap"
    "sigs.k8s.io/controller-runtime/pkg/webhook"

    utilruntime    "k8s.io/apimachinery/pkg/util/runtime"
    clientgoscheme "k8s.io/client-go/kubernetes/scheme"
    ctrl           "sigs.k8s.io/controller-runtime"
    logf           "sigs.k8s.io/controller-runtime/pkg/log"

    ibmv1 "github.com/ibm-security/verify-operator/api/v1"

    "github.com/ibm-security/verify-operator/controllers"
    //+kubebuilder:scaffold:imports
)

/*****************************************************************************/

var (
    scheme   = runtime.NewScheme()
    setupLog = ctrl.Log.WithName("setup")
)

/*****************************************************************************/

/*
 * Initialise the program.
 */

func init() {
    utilruntime.Must(clientgoscheme.AddToScheme(scheme))
    utilruntime.Must(ibmv1.AddToScheme(scheme))

    //+kubebuilder:scaffold:scheme
}
/*****************************************************************************/

/*
 * This function is used to determine the namespace in which the current
 * pod is running.
 */

func getLocalNamespace() (namespace string, err error) {
    var namespaceBytes []byte
    var clientCfg      *api.Config

    const k8sNamespaceFile string =
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    /*
     * Work out the namespace which should be used.  In a Kubernetes
     * environment we read this from the namespace file, otherwise we use
     * the default namespace in the kubectl file.
     */

    namespace = "default"

    namespaceBytes, err = ioutil.ReadFile(k8sNamespaceFile)

    if err != nil {
        clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

        if err != nil {
            return
        }

        namespace = clientCfg.Contexts[clientCfg.CurrentContext].Namespace
    } else {
        namespace = string(namespaceBytes)
    }

    return
}

/*****************************************************************************/

/*
 * Our main line.
 */

func main() {
    var metricsAddr          string
    var enableLeaderElection bool
    var probeAddr            string

    /*
     * Set up our various options.
     */

    flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", 
            "The address the metric endpoint binds to.")
    flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", 
            "The address the probe endpoint binds to.")
    flag.BoolVar(&enableLeaderElection, "leader-elect", false,
            "Enable leader election for controller manager. " +
            "Enabling this will ensure there is only one active controller " +
            "manager.")

    opts := zap.Options{
        Development: true,
    }

    opts.BindFlags(flag.CommandLine)

    flag.Parse()

    /*
     * Set the logger.
     */

    ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

    /*
     * Create the manager.
     */

    mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme:                 scheme,
        MetricsBindAddress:     metricsAddr,
        Port:                   9443,
        HealthProbeBindAddress: probeAddr,
        LeaderElection:         enableLeaderElection,
        LeaderElectionID:       "024cacd6.com",
    })

    if err != nil {
        setupLog.Error(err, "unable to start manager")
        os.Exit(1)
    }

    /*
     * Register our controller.
     */

    if err = (&controllers.IBMSecurityVerifyReconciler{
        Client: mgr.GetClient(),
        Log:    ctrl.Log.WithName("controllers").WithName("IBMSecurityVerify"),
        Scheme: mgr.GetScheme(),
    }).SetupWithManager(mgr); err != nil {
        setupLog.Error(err, "Unable to create the controller", 
                        "controller", "IBMSecurityVerify")
        os.Exit(1)
    }

    /*
     * Set up the Webhook manager for our API.  This WebHook is used to validate
     * the IBMSecurityVerify custom resources.
     */

    if err = (&ibmv1.IBMSecurityVerify{}).SetupWebhookWithManager(mgr); 
                                err != nil {
        setupLog.Error(err, "Unable to create a webhook", 
                                "webhook", "IBMSecurityVerify")

        os.Exit(1)
    }

    /*
     * Set up our health endpoints.
     */

    //+kubebuilder:scaffold:builder

    if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
        setupLog.Error(err, "unable to set up health check")
        os.Exit(1)
    }

    if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
        setupLog.Error(err, "unable to set up ready check")
        os.Exit(1)
    }

    /*
     * Register the Webhook which is used to annotate Ingress resources.
     */

    namespace, err := getLocalNamespace()

    if err != nil {
        setupLog.Error(err, "unable to determine the local namespace")
        os.Exit(1)
    }

    mgr.GetWebhookServer().Register("/mutate-v1-ingress", 
            &webhook.Admission{
                Handler: &ingressAnnotator{
                    client:    mgr.GetClient(),
                    log:       logf.Log.WithName("ingress-resource"),
                    namespace: namespace,
                },
            })

    /*
     * Initialise and start the OIDC server.
     */

    oidcServer := OidcServer{
        log:  logf.Log.WithName("OIDCServer"),
        cert: fmt.Sprintf("%s/%s", 
                        mgr.GetWebhookServer().CertDir, 
                        mgr.GetWebhookServer().CertName),
        key:  fmt.Sprintf("%s/%s", 
                        mgr.GetWebhookServer().CertDir, 
                        mgr.GetWebhookServer().KeyName),
    }

    go oidcServer.start()

    /*
     * Now we can start listening for requests.
     */

    setupLog.Info("starting manager")

    if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
        setupLog.Error(err, "problem running manager")
        os.Exit(1)
    }
}

/*****************************************************************************/

