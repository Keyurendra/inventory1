package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/accuknox/omniscan/pkg/config"
	"github.com/accuknox/omniscan/pkg/util"
)

const (
	artifactTokenFile = "/etc/accuknox-omni/artifact.tok"
	pollInterval      = 10 * time.Second
)

var dispatchCmd = &cli.Command{
	Name: "dispatch",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "config",
			Usage:    "Path to configuration file",
			Required: true,
		},
	},
	Action: runDispatch,
}

func runDispatch(ctx context.Context, c *cli.Command) error {
	cfg, err := config.Load(c.String("config"))
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	slog.InfoContext(
		ctx, "starting dispatcher",
		slog.String("namespace", cfg.Namespace),
		slog.Bool("skipMalwareScan", cfg.SkipMalwareScan),
		slog.Bool("skipVulnScan", cfg.SkipVulnScan),
	)

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("creating kube config: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	selector := labels.Everything()
	if cfg.NodeSelector != nil {
		selector, err = metav1.LabelSelectorAsSelector(cfg.NodeSelector)
		if err != nil {
			return fmt.Errorf("parsing node selector: %w", err)
		}
	}

	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Errorf("listing nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		slog.WarnContext(
			ctx, "no nodes found matching selector",
			slog.String("selector", selector.String()),
		)
		return nil
	}

	slog.InfoContext(ctx, "found nodes to scan", slog.Int("count", len(nodes.Items)))

	var ownerRef *metav1.OwnerReference
	dispatcherJobName := os.Getenv("DISPATCHER_JOB_NAME")
	if dispatcherJobName != "" {
		dispatcherJob, err := kubeClient.BatchV1().Jobs(cfg.Namespace).Get(
			ctx,
			dispatcherJobName,
			metav1.GetOptions{},
		)
		switch {
		case err != nil:
			slog.WarnContext(
				ctx,
				"failed to get dispatcher job, scan jobs will not have owner reference",
				slog.String("job", dispatcherJobName),
				slog.Any("error", err),
			)
		default:
			ownerRef = &metav1.OwnerReference{
				APIVersion:         "batch/v1",
				Kind:               "Job",
				Name:               dispatcherJob.Name,
				UID:                dispatcherJob.UID,
				BlockOwnerDeletion: util.Ptr(true),
				Controller:         util.Ptr(true),
			}
			slog.InfoContext(
				ctx, "configured owner reference for cascading deletion",
				slog.String("dispatcherJob", dispatcherJobName),
			)
		}
	}

	jobsToTrack, err := ensureScanJobs(ctx, kubeClient, cfg, nodes.Items, ownerRef)
	if err != nil {
		return fmt.Errorf("ensuring scan jobs: %w", err)
	}

	if len(jobsToTrack) == 0 {
		slog.InfoContext(ctx, "no jobs to track")
		return nil
	}

	slog.InfoContext(
		ctx, "waiting for scan jobs to complete",
		slog.Int("jobCount", len(jobsToTrack)),
	)

	return waitForJobsCompletion(ctx, kubeClient, cfg.Namespace, jobsToTrack)
}

func ensureScanJobs(ctx context.Context, kubeClient *kubernetes.Clientset, cfg *config.NodeScanConfig, nodes []corev1.Node, ownerRef *metav1.OwnerReference) ([]string, error) {
	var jobsToTrack []string
	var created, skipped int

	for _, node := range nodes {
		jobName := generateJobName(node.Name)

		_, err := kubeClient.BatchV1().Jobs(cfg.Namespace).Get(
			ctx,
			jobName,
			metav1.GetOptions{},
		)
		if err == nil {
			slog.InfoContext(
				ctx, "scan job already exists, will track",
				slog.String("node", node.Name),
				slog.String("job", jobName),
			)
			jobsToTrack = append(jobsToTrack, jobName)
			skipped++
			continue
		}

		if !isNotFoundError(err) {
			return nil, fmt.Errorf("checking job %s: %w", jobName, err)
		}

		os := node.Labels["kubernetes.io/os"]

		job := buildNodeScanJob(cfg, node.Name, jobName, os, ownerRef)
		_, err = kubeClient.BatchV1().Jobs(cfg.Namespace).Create(ctx, job, metav1.CreateOptions{})
		if err != nil {
			if isAlreadyExistsError(err) {
				slog.InfoContext(
					ctx, "job created by another process",
					slog.String("node", node.Name),
					slog.String("job", jobName),
				)
				jobsToTrack = append(jobsToTrack, jobName)
				skipped++
				continue
			}
			slog.ErrorContext(
				ctx, "failed to create job",
				slog.String("node", node.Name),
				slog.Any("error", err),
			)
			continue
		}

		slog.InfoContext(
			ctx, "created scan job",
			slog.String("node", node.Name),
			slog.String("job", jobName),
		)
		jobsToTrack = append(jobsToTrack, jobName)
		created++
	}

	slog.InfoContext(
		ctx, "job creation summary",
		slog.Int("created", created),
		slog.Int("skipped", skipped),
	)

	return jobsToTrack, nil
}

func waitForJobsCompletion(ctx context.Context, kubeClient *kubernetes.Clientset, namespace string, jobNames []string) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	pending := make(map[string]bool)
	for _, name := range jobNames {
		pending[name] = true
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for jobName := range pending {
				job, err := kubeClient.BatchV1().Jobs(namespace).Get(
					ctx,
					jobName,
					metav1.GetOptions{},
				)
				if err != nil {
					slog.ErrorContext(
						ctx, "error fetching job status",
						slog.String("job", jobName),
						slog.Any("error", err),
					)
					continue
				}

				if isJobFinished(job) {
					delete(pending, jobName)
					if isJobSucceeded(job) {
						slog.InfoContext(
							ctx, "scan job succeeded",
							slog.String("job", jobName),
						)
						continue
					}
					slog.WarnContext(
						ctx, "scan job failed",
						slog.String("job", jobName),
					)
				}
			}

			if len(pending) == 0 {
				slog.InfoContext(ctx, "all scan jobs completed")
				return nil
			}

			slog.InfoContext(
				ctx, "waiting for jobs",
				slog.Int("pending", len(pending)),
			)
		}
	}
}

func generateJobName(nodeName string) string {
	safeName := strings.ReplaceAll(nodeName, ".", "-")
	if len(safeName) > 40 {
		safeName = safeName[:40]
	}
	return fmt.Sprintf("node-scan-%s", safeName)
}

func buildNodeScanJob(cfg *config.NodeScanConfig, nodeName, jobName, os string, ownerRef *metav1.OwnerReference) *batchv1.Job {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "omniscan",
				"app.kubernetes.io/component": "node-scan",
				"omni.accuknox.com/node":      nodeName,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: util.Ptr(int32(86400)),
			BackoffLimit:            cfg.BackoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":      "omniscan",
						"app.kubernetes.io/component": "node-scan",
					},
				},
				Spec: corev1.PodSpec{
					NodeName:                     nodeName,
					AutomountServiceAccountToken: util.Ptr(false),
					RestartPolicy:                corev1.RestartPolicyOnFailure,
					Tolerations:                  cfg.Tolerations,
					ImagePullSecrets:             cfg.ImagePullSecrets,
					Containers: []corev1.Container{{
						Name:            "scan",
						Image:           cfg.Image,
						ImagePullPolicy: cfg.ImagePullPolicy,
						Command:         []string{"entrypoint-kubernetes-node-scan"},
						Resources:       cfg.Resources,
						SecurityContext: &corev1.SecurityContext{
							Privileged: util.Ptr(false),
							RunAsUser:  util.Ptr(int64(0)),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
						Env: buildEnvVars(cfg, nodeName, os),
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host-root",
								MountPath: "/mnt/rootfs",
								ReadOnly:  true,
							},
							{
								Name:      "artifact-token",
								MountPath: artifactTokenFile,
								SubPath:   "token",
								ReadOnly:  true,
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "host-root",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/",
									Type: util.Ptr(corev1.HostPathDirectory),
								},
							},
						},
						{
							Name: "artifact-token",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: cfg.ArtifactAPI.TokenSecretName,
								},
							},
						},
					},
				},
			},
		},
	}

	if ownerRef != nil {
		job.OwnerReferences = []metav1.OwnerReference{*ownerRef}
		job.Spec.TTLSecondsAfterFinished = nil
	}

	return job
}

func buildEnvVars(cfg *config.NodeScanConfig, nodeName, os string) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name:  "ARTIFACT_API_ENDPOINT",
			Value: cfg.ArtifactAPI.Endpoint,
		},
		{
			Name:  "ARTIFACT_API_TENANT_ID",
			Value: fmt.Sprint(cfg.ArtifactAPI.TenantID),
		},
		{
			Name:  "ARTIFACT_API_LABEL",
			Value: cfg.ArtifactAPI.Label,
		},
		{
			Name:  "ARTIFACT_API_SKIP_TLS_VERIFICATION",
			Value: fmt.Sprint(cfg.ArtifactAPI.SkipTLSVerification),
		},
		{
			Name:  "CLUSTER_NAME",
			Value: cfg.ClusterName,
		},
		{
			Name:  "NODE_NAME",
			Value: nodeName,
		},
		{
			Name:  "OS",
			Value: os,
		},
		{
			Name:  "SKIP_MALWARE_SCAN",
			Value: fmt.Sprint(cfg.SkipMalwareScan),
		},
		{
			Name:  "SKIP_VULN_SCAN",
			Value: fmt.Sprint(cfg.SkipVulnScan),
		},
		{
			Name:  "VULN_DB_REPOSITORY",
			Value: cfg.Repository.VulnDB,
		},
		{
			Name:  "MSRC_DB_REPOSITORY",
			Value: cfg.Repository.MsrcDB,
		},
		{
			Name:  "CLAMAV_DB_REPOSITORY",
			Value: cfg.Repository.ClamavDB,
		},
		{
			Name:  "REPOSITORY_SKIP_TLS_VERIFICATION",
			Value: fmt.Sprint(cfg.Repository.SkipTLSVerification),
		},
		{
			Name:  "REPOSITORY_PLAIN_HTTP",
			Value: fmt.Sprint(cfg.Repository.PlainHTTP),
		},
	}
	return append(env, cfg.AdditionalEnv...)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}

func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already exists")
}

func isJobFinished(job *batchv1.Job) bool {
	for _, cond := range job.Status.Conditions {
		if cond.Type != batchv1.JobComplete && cond.Type != batchv1.JobFailed {
			continue
		}
		return cond.Status == corev1.ConditionTrue
	}
	return false
}

func isJobSucceeded(job *batchv1.Job) bool {
	for _, cond := range job.Status.Conditions {
		if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
