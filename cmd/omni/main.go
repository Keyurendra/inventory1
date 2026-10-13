package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/urfave/cli/v3"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/accuknox/omniscan/cmd/omni/agent"
	"github.com/accuknox/omniscan/cmd/omni/aws"
	"github.com/accuknox/omniscan/cmd/omni/azure"
	"github.com/accuknox/omniscan/cmd/omni/db"
	"github.com/accuknox/omniscan/cmd/omni/gcp"
	"github.com/accuknox/omniscan/cmd/omni/openshift"
	"github.com/accuknox/omniscan/internal/controller"
	"github.com/accuknox/omniscan/pkg/util"

	// import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	omniv1alpha1 "github.com/accuknox/omniscan/api/v1alpha1"
	webhookv1alpha1 "github.com/accuknox/omniscan/internal/webhook/v1alpha1"
	// +kubebuilder:scaffold:imports
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(omniv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	ctx := context.Background()
	err := cmd.Run(ctx, os.Args)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}
}

var (
	scheme                                           = runtime.NewScheme()
	setupLog                                         = ctrl.Log.WithName("setup")
	metricsAddr                                      string
	metricsCertPath, metricsCertName, metricsCertKey string
	webhookCertPath, webhookCertName, webhookCertKey string
	enableLeaderElection                             bool
	probeAddr                                        string
	secureMetrics                                    bool
	enableHTTP2                                      bool
	tlsOpts                                          []func(*tls.Config)
)

const omniRepo = "public.ecr.aws/k9v9d5v2/omni"

var version = "latest"

func omniImage(tag string) string {
	return omniRepo + ":" + tag
}

var cmd = &cli.Command{
	Name:                  "omni",
	Usage:                 "Multi-platform VM Scanner",
	EnableShellCompletion: true,
	Authors:               []any{"AccuKnox Inc."},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Usage: "Set log level: debug, info, warn, error",
			Value: "info",
		},
		&cli.StringFlag{
			Name:  "log-format",
			Usage: "Set log format: text, json, pretty",
			Value: "text",
		},
		&cli.BoolFlag{
			Name:  "log-with-source",
			Usage: "Include source file and line number in log messages",
			Value: false,
		},
	},
	Commands: []*cli.Command{
		db.NewCommand(),
		agent.NewCommand(),
		aws.NewCommand(),
		gcp.NewCommand(),
		azure.NewCommand(),
		{
			Name: "openshift",
			Commands: []*cli.Command{
				openshift.NewScanCommand(),
				openshift.NewOrchestrateCommand(),
				openshift.NewScheduleCommand(),
				operatorCmd,
			},
		},
	},
	Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
		level := c.String("log-level")
		if level != "debug" && level != "info" && level != "error" {
			return ctx, fmt.Errorf("invalid log level %q", level)
		}
		format := c.String("log-format")
		if format != "text" && format != "json" && format != "pretty" {
			return ctx, fmt.Errorf("invalid log format %q", format)
		}
		withSource := c.Bool("log-with-source")
		slog.SetDefault(util.NewLogger(level, format, withSource))
		return ctx, nil
	},
}

var operatorCmd = &cli.Command{
	Name: "operator",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "metrics-bind-address",
			Value:       "0",
			Destination: &metricsAddr,
		},
		&cli.StringFlag{
			Name:        "health-probe-bind-address",
			Value:       ":8081",
			Destination: &probeAddr,
		},
		&cli.BoolFlag{
			Name:        "leader-elect",
			Value:       false,
			Destination: &enableLeaderElection,
		},
		&cli.BoolFlag{
			Name:        "metrics-secure",
			Value:       true,
			Destination: &secureMetrics,
		},
		&cli.StringFlag{
			Name:        "webhook-cert-path",
			Destination: &webhookCertPath,
		},
		&cli.StringFlag{
			Name:        "webhook-cert-name",
			Value:       "tls.crt",
			Destination: &webhookCertName,
		},
		&cli.StringFlag{
			Name:        "webhook-cert-key",
			Value:       "tls.key",
			Destination: &webhookCertKey,
		},
		&cli.StringFlag{
			Name:        "metrics-cert-path",
			Destination: &metricsCertPath,
		},
		&cli.StringFlag{
			Name:        "metrics-cert-name",
			Value:       "tls.crt",
			Destination: &metricsCertName,
		},
		&cli.StringFlag{
			Name:        "metrics-cert-key",
			Value:       "tls.key",
			Destination: &metricsCertKey,
		},
		&cli.BoolFlag{
			Name:        "enable-http2",
			Value:       false,
			Destination: &enableHTTP2,
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

		// if the enable-http2 flag is false (the default), http/2 should be
		// disabled due to its vulnerabilities. More specifically, disabling
		// http/2 will prevent from being vulnerable to the HTTP/2 Stream
		// Cancellation and Rapid Reset CVEs. For more information see:
		// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
		// - https://github.com/advisories/GHSA-4374-p667-p6c8
		disableHTTP2 := func(c *tls.Config) {
			setupLog.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		}

		if !enableHTTP2 {
			tlsOpts = append(tlsOpts, disableHTTP2)
		}

		// create watchers for metrics and webhooks certificates
		var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

		// initial webhook TLS options
		webhookTLSOpts := tlsOpts

		if len(webhookCertPath) > 0 {
			setupLog.Info(
				"Initializing webhook certificate watcher using provided certificates",
				"webhook-cert-path", webhookCertPath,
				"webhook-cert-name", webhookCertName,
				"webhook-cert-key", webhookCertKey,
			)

			var err error
			webhookCertWatcher, err = certwatcher.New(
				filepath.Join(webhookCertPath, webhookCertName),
				filepath.Join(webhookCertPath, webhookCertKey),
			)
			if err != nil {
				setupLog.Error(err, "Failed to initialize webhook certificate watcher")
				os.Exit(1)
			}

			webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
				config.GetCertificate = webhookCertWatcher.GetCertificate
			})
		}

		webhookServer := webhook.NewServer(webhook.Options{
			TLSOpts: webhookTLSOpts,
		})

		// Metrics endpoint is enabled in 'config/default/kustomization.yaml'.
		// The Metrics options configure the server. More info:
		// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
		// - https://book.kubebuilder.io/reference/metrics.html
		metricsServerOptions := metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		}

		if secureMetrics {
			// FilterProvider is used to protect the metrics endpoint with
			// authn/authz. These configurations ensure that only authorized
			// users and service accounts can access the metrics endpoint. The
			// RBAC are configured in 'config/rbac/kustomization.yaml'.
			// More info:
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
			metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
		}

		// If the certificate is not specified, controller-runtime will
		// automatically generate self-signed certificates for the metrics
		// server. While convenient for development and testing, this setup is
		// not recommended for production.
		//
		// TODO(user): If you enable certManager, uncomment the following lines:
		// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to
		// 	generate and use certificates managed by cert-manager for the
		// metrics server.
		// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml
		// for TLS certification.
		if len(metricsCertPath) > 0 {
			setupLog.Info(
				"Initializing metrics certificate watcher using provided certificates",
				"metrics-cert-path", metricsCertPath,
				"metrics-cert-name", metricsCertName,
				"metrics-cert-key", metricsCertKey,
			)

			var err error
			metricsCertWatcher, err = certwatcher.New(
				filepath.Join(metricsCertPath, metricsCertName),
				filepath.Join(metricsCertPath, metricsCertKey),
			)
			if err != nil {
				setupLog.Error(
					err, "to initialize metrics certificate watcher",
					"error", err,
				)
				os.Exit(1)
			}

			metricsServerOptions.TLSOpts = append(
				metricsServerOptions.TLSOpts,
				func(config *tls.Config) {
					config.GetCertificate = metricsCertWatcher.GetCertificate
				},
			)
		}

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:                 scheme,
			Metrics:                metricsServerOptions,
			WebhookServer:          webhookServer,
			HealthProbeBindAddress: probeAddr,
			LeaderElection:         enableLeaderElection,
			LeaderElectionID:       "8c8cbb39.omni.accuknox.com",
			// LeaderElectionReleaseOnCancel defines if the leader should step
			// down voluntarily when the Manager ends. This requires the binary
			// to immediately end when the Manager is stopped, otherwise, this
			// setting is unsafe. Setting this significantly speeds up
			// voluntary leader transitions as the new leader don't have to
			// wait LeaseDuration time first.
			// In the default scaffold provided, the program ends immediately
			// after the manager stops, so would be fine to enable this option.
			// However, if you are doing or is intended to do any operation
			// such as perform cleanups after the manager stops then its usage
			// might be unsafe.
			// LeaderElectionReleaseOnCancel: true,
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		schedule := &controller.ScheduleReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}
		if err := schedule.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Schedule")
			os.Exit(1)
		}

		scan := &controller.ScanReconciler{
			Client:     mgr.GetClient(),
			Scheme:     mgr.GetScheme(),
			KubeClient: kubernetes.NewForConfigOrDie(ctrl.GetConfigOrDie()),
		}
		if err := scan.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Scan")
			os.Exit(1)
		}

		// nolint:goconst
		if os.Getenv("ENABLE_WEBHOOKS") != "false" {
			image := omniImage(version)
			err := webhookv1alpha1.SetupScanWebhookWithManager(mgr, image)
			if err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "Scan")
				os.Exit(1)
			}
			err = webhookv1alpha1.SetupScheduleWebhookWithManager(mgr, image)
			if err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "Schedule")
				os.Exit(1)
			}
		}

		// +kubebuilder:scaffold:builder

		if metricsCertWatcher != nil {
			setupLog.Info("Adding metrics certificate watcher to manager")
			if err := mgr.Add(metricsCertWatcher); err != nil {
				setupLog.Error(err, "unable to add metrics certificate watcher to manager")
				os.Exit(1)
			}
		}

		if webhookCertWatcher != nil {
			setupLog.Info("Adding webhook certificate watcher to manager")
			if err := mgr.Add(webhookCertWatcher); err != nil {
				setupLog.Error(err, "unable to add webhook certificate watcher to manager")
				os.Exit(1)
			}
		}

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			setupLog.Error(err, "unable to set up health check")
			os.Exit(1)
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			setupLog.Error(err, "unable to set up ready check")
			os.Exit(1)
		}

		setupLog.Info("starting manager")
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}

		return nil
	},
}
