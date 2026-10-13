/*
Copyright 2025 AccuKnox Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	volumesnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	securityv1 "github.com/openshift/api/security/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/accuknox/omniscan/api/v1alpha1"
	kubeUtil "github.com/accuknox/omniscan/pkg/job/kube/util"
	"github.com/accuknox/omniscan/pkg/util"
)

const (
	jobTypeOrch = iota
	jobTypeScan

	requeueDelay = 30 * time.Second

	// annotations set by orchestration job to track created resources.
	annotationSnapshot = "omni.accuknox.com/snapshotName"
	annotationPVC      = "omni.accuknox.com/clonedPVCName"

	// finalizers for cleanup coordination.
	finalizerOmni     = "omni.accuknox.com/termination"
	finalizerSnapshot = "snapshot.storage.kubernetes.io/volumesnapshot-bound-protection"
	finalizerPVC      = "kubernetes.io/pvc-protection"
)

var (
	errMissingPVCAnnotation      = errors.New("missing cloned PVC name annotation")
	errMissingSnapshotAnnotation = errors.New("missing snapshot name annotation")
)

// ScanReconciler reconciles Scan resources.
type ScanReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	KubeClient kubernetes.Interface
}

// +kubebuilder:rbac:groups=omni.accuknox.com,resources=scans,verbs=get;list;watch;patch;update
// +kubebuilder:rbac:groups=omni.accuknox.com,resources=scans/status,verbs=patch;update
// +kubebuilder:rbac:groups=omni.accuknox.com,resources=scans/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;patch;delete
// +kubebuilder:rbac:groups=snapshot.storage.k8s.io,resources=volumesnapshots,verbs=get;list;watch;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=create
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;patch
// +kubebuilder:rbac:groups="snapshot.storage.k8s.io",resources=volumesnapshots,verbs=create
// +kubebuilder:rbac:groups="kubevirt.io",resources=virtualmachines,verbs=get
// +kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,verbs=get;list;patch;watch

// Reconcile performs the main reconciliation loop for Scan resources.
func (r *ScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := slog.New(logr.ToSlogHandler(log.FromContext(ctx)))

	scan := &v1alpha1.Scan{}
	if err := r.Get(ctx, req.NamespacedName, scan); err != nil {
		if apierr.IsNotFound(err) {
			log.DebugContext(ctx, "scan CR deleted",
				slog.String("name", req.Name),
				slog.String("namespace", req.Namespace))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get scan: %w", err)
	}

	if err := r.ensureFinalizer(ctx, scan); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure finalizer: %w", err)
	}

	if scan.DeletionTimestamp != nil && !scan.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, scan)
	}

	return r.reconcileScan(ctx, req, scan)
}

// SetupWithManager registers the controller with the manager.
func (r *ScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := volumesnapshotv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add volumesnapshot scheme: %w", err)
	}

	// fail silently if not on Openshift
	_ = securityv1.AddToScheme(mgr.GetScheme())

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Scan{}).
		Named("scan").
		Complete(r)
}

// ensureFinalizer adds the omni finalizer if not present.
func (r *ScanReconciler) ensureFinalizer(ctx context.Context, scan *v1alpha1.Scan) error {
	patch := client.MergeFrom(scan.DeepCopy())
	if !ctrlutil.AddFinalizer(scan, finalizerOmni) {
		return nil
	}
	if err := r.Patch(ctx, scan, patch); err != nil && !apierr.IsNotFound(err) {
		return fmt.Errorf("patch scan: %w", err)
	}
	return nil
}

// handleDeletion cleans up resources and removes finalizers during Scan deletion.
func (r *ScanReconciler) handleDeletion(ctx context.Context, scan *v1alpha1.Scan) (ctrl.Result, error) {
	hash, err := scan.Hash()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("compute scan hash: %w", err)
	}

	orchJobName := kubeUtil.JobName(scan.Name, "orch", hash)
	if err := r.cleanupJob(ctx, scan.Namespace, orchJobName); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup orch job: %w", err)
	}

	scanJobName := kubeUtil.JobName(scan.Name, "scan", hash)
	if err := r.cleanupJob(ctx, scan.Namespace, scanJobName); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup scan job: %w", err)
	}

	patch := client.MergeFrom(scan.DeepCopy())
	if ctrlutil.RemoveFinalizer(scan, finalizerOmni) {
		if err := r.Patch(ctx, scan, patch); err != nil && !apierr.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// cleanupJob removes finalizer from job and cleans up its associated resources.
func (r *ScanReconciler) cleanupJob(ctx context.Context, ns, name string) error {
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: ns, Name: name}

	if err := r.Get(ctx, key, job); err != nil {
		if apierr.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get job: %w", err)
	}

	saName := job.Spec.Template.Spec.ServiceAccountName
	if saName != "" {
		sa := &corev1.ServiceAccount{}
		saKey := types.NamespacedName{Namespace: ns, Name: saName}
		if err := r.Get(ctx, saKey, sa); err == nil {
			if err := r.cleanupSCCUser(ctx, sa); err != nil {
				slog.WarnContext(
					ctx,
					"failed to cleanup SCC user",
					slog.String("sa", saName),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	if err := r.removeFinalizer(ctx, job, finalizerOmni); err != nil {
		return fmt.Errorf("remove job finalizer: %w", err)
	}

	if err := r.cleanupResources(ctx, ns, job.GetAnnotations()); err != nil {
		return fmt.Errorf("cleanup resources: %w", err)
	}

	return nil
}

// reconcileScan orchestrates the two-stage scan process: orchestration job followed by scan job.
func (r *ScanReconciler) reconcileScan(ctx context.Context, req ctrl.Request, scan *v1alpha1.Scan) (ctrl.Result, error) {
	orchJob, isNew, err := r.ensureJob(ctx, scan, nil)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure orch job: %w", err)
	}
	if isNew {
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	if !isJobFinished(orchJob) {
		if err := r.updatePhaseFromJob(ctx, req, scan, orchJob); err != nil {
			return ctrl.Result{}, fmt.Errorf("update phase: %w", err)
		}
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	if isJobFailed(orchJob) {
		return r.handleOrchFailure(ctx, scan, orchJob)
	}

	cond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionOrchestrationJobFinished,
		Status:  corev1.ConditionTrue,
		Reason:  "Completed",
		Message: fmt.Sprintf("orchestration job %s completed", orchJob.Name),
	}
	if _, err := r.updateCondition(ctx, req.NamespacedName, cond); err != nil {
		return ctrl.Result{}, fmt.Errorf("update condition: %w", err)
	}

	if err := r.validateOrchJobAnnotations(ctx, scan, orchJob); err != nil {
		return ctrl.Result{}, err
	}

	scanJob, isNew, err := r.ensureJob(ctx, scan, orchJob)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure scan job: %w", err)
	}
	if isNew {
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	if isJobFailed(scanJob) {
		return r.handleScanFailure(ctx, scan, scanJob, orchJob)
	}

	if isJobFinished(scanJob) {
		return r.handleScanSuccess(ctx, scan, scanJob, orchJob)
	}

	return ctrl.Result{RequeueAfter: requeueDelay}, nil
}

// validateOrchJobAnnotations checks that orchestration job has required resource annotations.
func (r *ScanReconciler) validateOrchJobAnnotations(ctx context.Context, scan *v1alpha1.Scan, job *batchv1.Job) error {
	if _, ok := job.Annotations[annotationPVC]; !ok {
		return r.handleMissingPVC(ctx, scan, job)
	}
	if _, ok := job.Annotations[annotationSnapshot]; !ok {
		return r.handleMissingSnapshot(ctx, scan, job)
	}
	return nil
}

// handleScanSuccess marks the scan as succeeded and cleans up resources.
func (r *ScanReconciler) handleScanSuccess(ctx context.Context, scan *v1alpha1.Scan, scanJob, orchJob *batchv1.Job) (ctrl.Result, error) {
	key := types.NamespacedName{Namespace: scan.Namespace, Name: scan.Name}
	cond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionScanJobFinished,
		Status:  corev1.ConditionTrue,
		Reason:  "Completed",
		Message: fmt.Sprintf("scan job %s completed", scanJob.Name),
	}
	if _, err := r.updateCondition(ctx, key, cond); err != nil {
		return ctrl.Result{}, fmt.Errorf("update condition: %w", err)
	}

	if err := r.removeFinalizer(ctx, orchJob, finalizerOmni); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove orch job finalizer: %w", err)
	}

	if err := r.removeFinalizer(ctx, scanJob, finalizerOmni); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove scan job finalizer: %w", err)
	}

	if err := r.cleanupResources(ctx, scan.Namespace, scanJob.Annotations); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup resources: %w", err)
	}

	if err := r.updatePhase(ctx, key, v1alpha1.ScanPhaseSucceeded); err != nil {
		return ctrl.Result{}, fmt.Errorf("update phase: %w", err)
	}

	return ctrl.Result{}, nil
}

// updatePhase updates the scan phase and sets completion time for terminal states.
func (r *ScanReconciler) updatePhase(ctx context.Context, key types.NamespacedName, phase v1alpha1.ScanPhase) error {
	scan := &v1alpha1.Scan{}
	if err := r.Get(ctx, key, scan); err != nil {
		return fmt.Errorf("get scan: %w", err)
	}

	patch := client.MergeFrom(scan.DeepCopy())
	scan.Status.Phase = phase
	if phase == v1alpha1.ScanPhaseSucceeded || phase == v1alpha1.ScanPhaseFailed {
		now := metav1.Now()
		scan.Status.CompletionTime = &now
	}

	return r.Status().Patch(ctx, scan, patch)
}

// updatePhaseFromJob updates scan phase based on job state, setting start time if available.
func (r *ScanReconciler) updatePhaseFromJob(ctx context.Context, req ctrl.Request, scan *v1alpha1.Scan, job *batchv1.Job) error {
	if err := r.Get(ctx, req.NamespacedName, scan); err != nil {
		return fmt.Errorf("get scan: %w", err)
	}

	patch := client.MergeFrom(scan.DeepCopy())
	phase := v1alpha1.ScanPhasePending
	if job.Status.StartTime != nil {
		scan.Status.StartTime = job.Status.StartTime
		phase = v1alpha1.ScanPhaseRunning
	}
	scan.Status.Phase = phase

	return r.Status().Patch(ctx, scan, patch)
}

// updateCondition adds or updates a condition in the scan status.
func (r *ScanReconciler) updateCondition(ctx context.Context, key types.NamespacedName, cond v1alpha1.ScanCondition) (*v1alpha1.Scan, error) {
	scan := &v1alpha1.Scan{}
	if err := r.Get(ctx, key, scan); err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}

	patch := client.MergeFrom(scan.DeepCopy())
	scan.Status.SetCondition(cond)

	return scan, r.Status().Patch(ctx, scan, patch)
}

// ensureJob creates or retrieves a job (orchestration or scan) with its service account.
func (r *ScanReconciler) ensureJob(ctx context.Context, scan *v1alpha1.Scan, parent *batchv1.Job) (*batchv1.Job, bool, error) {
	typ := jobTypeOrch
	if parent != nil {
		typ = jobTypeScan
	}

	hash, err := scan.Hash()
	if err != nil {
		return nil, false, fmt.Errorf("compute scan hash: %w", err)
	}

	isNew, err := r.ensureRole(ctx, scan, typ)
	if err != nil {
		return nil, false, fmt.Errorf("ensure role: %w", err)
	}
	if isNew {
		return nil, true, nil
	}

	sa, isNew, err := r.ensureSvcAcct(ctx, scan, typ)
	if err != nil {
		return nil, false, fmt.Errorf("ensure service account: %w", err)
	}
	if isNew {
		return nil, true, nil
	}

	name, spec := r.buildJobSpec(scan, hash, parent)
	job := &batchv1.Job{}
	key := types.NamespacedName{Namespace: scan.Namespace, Name: name}

	if err := r.Get(ctx, key, job); err != nil {
		if !apierr.IsNotFound(err) {
			return nil, false, fmt.Errorf("get job: %w", err)
		}

		job = r.newJob(scan, sa, name, spec)
		if err := ctrl.SetControllerReference(scan, job, r.Scheme); err != nil {
			return nil, false, fmt.Errorf("set controller reference: %w", err)
		}

		ctrlutil.AddFinalizer(job, finalizerOmni)

		if err := r.Create(ctx, job); err != nil {
			typ := jobTypeOrch
			if parent != nil {
				typ = jobTypeScan
			}
			r.setJobCreationCondition(ctx, types.NamespacedName{
				Namespace: scan.Namespace,
				Name:      scan.Name,
			}, typ, false, err.Error())
			return nil, false, fmt.Errorf("create job: %w", err)
		}

		r.setJobCreationCondition(ctx, types.NamespacedName{
			Namespace: scan.Namespace,
			Name:      scan.Name,
		}, typ, true, "Job created")

		return job, true, nil
	}

	return job, false, nil
}

// buildJobSpec returns the job name and spec based on whether it's an orchestration or scan job.
func (r *ScanReconciler) buildJobSpec(scan *v1alpha1.Scan, hash string, parent *batchv1.Job) (string, jobSpec) {
	if parent == nil {
		return r.buildOrchJobSpec(scan, hash)
	}
	return r.buildScanJobSpec(scan, hash, parent)
}

// buildOrchJobSpec creates spec for the orchestration job that prepares snapshot and PVC.
func (r *ScanReconciler) buildOrchJobSpec(scan *v1alpha1.Scan, hash string) (string, jobSpec) {
	name := kubeUtil.JobName(scan.Name, "orch", hash)
	return name, jobSpec{
		ctrName: "orchestration",
		command: []string{"omni"},
		args: []string{
			"openshift", "orchestrate",
			"--name=" + scan.Name,
			"--namespace=" + scan.Namespace,
		},
	}
}

// buildScanJobSpec creates spec for the scan job that performs the actual scanning.
func (r *ScanReconciler) buildScanJobSpec(scan *v1alpha1.Scan, hash string, parent *batchv1.Job) (string, jobSpec) {
	name := kubeUtil.JobName(scan.Name, "scan", hash)
	annotations := map[string]string{
		annotationSnapshot: parent.Annotations[annotationSnapshot],
		annotationPVC:      parent.Annotations[annotationPVC],
	}

	devicePath := "/dev/" + uuid.NewString()

	var skipMalwareScan bool
	if scan.Spec.SkipMalwareScan != nil {
		skipMalwareScan = *scan.Spec.SkipMalwareScan
	}

	return name, jobSpec{
		ctrName: "scan",
		command: []string{"entrypoint-openshift"},
		args: []string{
			devicePath,
			"--name=" + scan.Name,
			"--namespace=" + scan.Namespace,
			"--artifact-token-file=/etc/omni/artifact.tok",
		},
		vols: []corev1.Volume{
			{
				Name: "target-disk",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: annotations[annotationPVC],
						ReadOnly:  true,
					},
				},
			},
			{
				Name: "artifact-token",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: scan.Spec.ArtifactAPI.Token.SecretRef.Name,
						Items: []corev1.KeyToPath{
							{
								Key:  scan.Spec.ArtifactAPI.Token.SecretRef.Key,
								Path: "artifact.tok",
							},
						},
					},
				},
			},
		},
		volDevices: []corev1.VolumeDevice{{
			Name:       "target-disk",
			DevicePath: devicePath,
		}},
		volMounts: []corev1.VolumeMount{{
			Name:      "artifact-token",
			MountPath: "/etc/omni/artifact.tok",
			SubPath:   "artifact.tok",
			ReadOnly:  true,
		}},
		securityContext: &corev1.SecurityContext{
			Privileged: util.Ptr(true),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  []corev1.Capability{"SYS_ADMIN", "MKNOD"},
			},
			RunAsUser: util.Ptr(int64(0)),
		},
		annotations: annotations,
		env: []corev1.EnvVar{
			{
				Name:  "ARTIFACT_API_ENDPOINT",
				Value: scan.Spec.ArtifactAPI.Endpoint,
			},
			{
				Name:  "ARTIFACT_API_TENANT_ID",
				Value: fmt.Sprint(scan.Spec.ArtifactAPI.TenantID),
			},
			{
				Name:  "ARTIFACT_API_LABEL",
				Value: scan.Spec.ArtifactAPI.Label,
			},
			{
				Name:  "SKIP_MALWARE_SCAN",
				Value: fmt.Sprint(skipMalwareScan),
			},
		},
	}
}

// jobSpec holds the specification components for building a job.
type jobSpec struct {
	ctrName         string
	command         []string
	args            []string
	vols            []corev1.Volume
	volDevices      []corev1.VolumeDevice
	volMounts       []corev1.VolumeMount
	securityContext *corev1.SecurityContext
	annotations     map[string]string
	env             []corev1.EnvVar
}

// newJob constructs a Job resource from the scan and spec.
func (r *ScanReconciler) newJob(scan *v1alpha1.Scan, sa *corev1.ServiceAccount, name string, spec jobSpec) *batchv1.Job {
	annotations := make(map[string]string, len(spec.annotations)+len(scan.Annotations))
	maps.Copy(annotations, scan.Annotations)
	maps.Copy(annotations, spec.annotations)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   scan.Namespace,
			Labels:      scan.Labels,
			Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: scan.Spec.BackoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      scan.Labels,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: sa.Name,
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{{
						Name:            spec.ctrName,
						SecurityContext: spec.securityContext,
						Image:           scan.Spec.Image,
						ImagePullPolicy: scan.Spec.ImagePullPolicy,
						Resources:       scan.Spec.Resources,
						Command:         spec.command,
						Args:            spec.args,
						VolumeDevices:   spec.volDevices,
						VolumeMounts:    spec.volMounts,
						Env:             spec.env,
					}},
					Volumes: spec.vols,
				},
			},
		},
	}
}

// setJobCreationCondition updates the scan condition based on job creation success or failure.
func (r *ScanReconciler) setJobCreationCondition(ctx context.Context, req types.NamespacedName, typ int, success bool, msg string) {
	status := corev1.ConditionFalse
	reason := "FailedToCreate"
	if success {
		status = corev1.ConditionTrue
		reason = "JobCreated"
	}

	condType := v1alpha1.ScanConditionOrchestrationJobCreated
	if typ == jobTypeScan {
		condType = v1alpha1.ScanConditionScanJobCreated
	}

	r.updateCondition(ctx, req, v1alpha1.ScanCondition{
		Type:    condType,
		Status:  status,
		Reason:  reason,
		Message: msg,
	})
}

// ensureSvcAcct creates or retrieves the service account for the scan jobs.
func (r *ScanReconciler) ensureSvcAcct(ctx context.Context, scan *v1alpha1.Scan, typ int) (*corev1.ServiceAccount, bool, error) {
	hash, err := scan.Hash()
	if err != nil {
		return nil, false, fmt.Errorf("compute scan hash: %w", err)
	}

	mid := "orch"
	if typ == jobTypeScan {
		mid = "scan"
	}

	name := kubeUtil.JobName(scan.Name, mid, hash)

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   scan.Namespace,
			Labels:      scan.Labels,
			Annotations: scan.Annotations,
		},
	}

	if err := ctrl.SetControllerReference(scan, sa, r.Scheme); err != nil {
		return nil, false, fmt.Errorf("set controller reference: %w", err)
	}

	if err := r.Create(ctx, sa); err != nil {
		if !apierr.IsAlreadyExists(err) {
			return nil, false, fmt.Errorf("creating service account: %w", err)
		}
		isNew, err := r.ensureRoleBinding(ctx, scan, sa)
		if err != nil {
			return nil, false, fmt.Errorf("ensure role binding: %w", err)
		}
		if err := r.ensureSCC(ctx, sa, typ); err != nil {
			return nil, false, fmt.Errorf("ensure scc: %w", err)
		}
		return sa, isNew, nil
	}

	if err := r.ensureSCC(ctx, sa, typ); err != nil {
		return nil, false, fmt.Errorf("ensure scc: %w", err)
	}

	return sa, true, nil
}

// ensureRole creates the scan role if it doesn't exist.
func (r *ScanReconciler) ensureRole(ctx context.Context, scan *v1alpha1.Scan, typ int) (bool, error) {
	hash, err := scan.Hash()
	if err != nil {
		return false, fmt.Errorf("compute scan hash: %w", err)
	}

	mid := "orch"
	if typ == jobTypeScan {
		mid = "scan"
	}

	name := kubeUtil.JobName(scan.Name, mid, hash)

	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"omni.accuknox.com"},
			Resources: []string{"scans"},
			Verbs:     []string{"get", "patch", "update"},
		},
		{
			APIGroups: []string{"omni.accuknox.com"},
			Resources: []string{"scans/status"},
			Verbs:     []string{"patch", "update"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"persistentvolumeclaims"},
			Verbs:     []string{"get", "list", "create", "delete", "watch"},
		},
		{
			APIGroups: []string{"snapshot.storage.k8s.io"},
			Resources: []string{"volumesnapshots"},
			Verbs:     []string{"get", "list", "create", "delete", "watch"},
		},
		{
			APIGroups: []string{"kubevirt.io"},
			Resources: []string{"virtualmachines"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"patch"},
		},
	}
	if typ == jobTypeScan {
		rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"scans"},
				Verbs:     []string{"get", "patch", "update"},
			},
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"scans/status"},
				Verbs:     []string{"patch", "update"},
			},
		}
	}

	cr := &rbacv1.Role{}
	key := types.NamespacedName{Name: name, Namespace: scan.Namespace}

	desired := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: scan.Namespace,
			Labels:    scan.GetLabels(),
		},
		Rules: rules,
	}
	if err := ctrl.SetControllerReference(scan, desired, r.Scheme); err != nil {
		return false, fmt.Errorf("set controller reference: %w", err)
	}

	if err := r.Get(ctx, key, cr); err != nil {
		if !apierr.IsNotFound(err) {
			return false, fmt.Errorf("get role: %w", err)
		}
		if err := r.Create(ctx, desired); err != nil {
			if apierr.IsAlreadyExists(err) {
				goto Patch
			}
			return false, fmt.Errorf("create role: %w", err)
		}
		return true, nil
	}

Patch:
	patch := client.MergeFrom(cr.DeepCopy())
	cr.Name = desired.Name
	cr.Namespace = desired.Namespace
	cr.Rules = desired.Rules
	if err := r.Patch(ctx, cr, patch); err != nil {
		return false, fmt.Errorf("patch role: %w", err)
	}

	return false, nil
}

// ensureRoleBinding creates the role binding for the service account.
func (r *ScanReconciler) ensureRoleBinding(ctx context.Context, scan *v1alpha1.Scan, sa *corev1.ServiceAccount) (bool, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sa.Name,
			Namespace:   sa.Namespace,
			Labels:      sa.Labels,
			Annotations: sa.Annotations,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     sa.Name,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      sa.Name,
			Namespace: sa.Namespace,
		}},
	}
	if err := ctrl.SetControllerReference(scan, rb, r.Scheme); err != nil {
		return false, fmt.Errorf("set controller reference: %w", err)
	}
	if err := r.Create(ctx, rb); err != nil {
		if apierr.IsAlreadyExists(err) {
			return false, nil
		}
		return false, fmt.Errorf("creating role binding: %w", err)
	}
	return true, nil
}

// handleOrchFailure marks the scan as failed when orchestration job fails.
func (r *ScanReconciler) handleOrchFailure(ctx context.Context, scan *v1alpha1.Scan, job *batchv1.Job) (ctrl.Result, error) {
	msg := fmt.Sprintf("orchestration job %s/%s failed", job.Namespace, job.Name)
	key := types.NamespacedName{Namespace: scan.Namespace, Name: scan.Name}
	cond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionOrchestrationJobFinished,
		Status:  corev1.ConditionFalse,
		Reason:  "Failed",
		Message: msg,
	}
	if _, err := r.updateCondition(ctx, key, cond); err != nil {
		return ctrl.Result{}, fmt.Errorf("update condition: %w", err)
	}

	if err := r.updatePhase(ctx, key, v1alpha1.ScanPhaseFailed); err != nil {
		return ctrl.Result{}, fmt.Errorf("update phase: %w", err)
	}

	if err := r.removeFinalizer(ctx, job, finalizerOmni); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove job finalizer: %w", err)
	}

	if err := r.cleanupResources(ctx, scan.Namespace, job.GetAnnotations()); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup resources: %w", err)
	}

	return ctrl.Result{}, errors.New(msg)
}

// handleMissingPVC marks the scan as failed when orchestration job completes without PVC annotation.
func (r *ScanReconciler) handleMissingPVC(ctx context.Context, scan *v1alpha1.Scan, job *batchv1.Job) error {
	key := types.NamespacedName{Namespace: scan.Namespace, Name: scan.Name}
	r.updateCondition(ctx, key, v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionClonedPVCReady,
		Status:  corev1.ConditionFalse,
		Reason:  "NoPVC",
		Message: "orchestration job completed but cloned PVC name annotation is missing",
	})

	r.updatePhase(ctx, key, v1alpha1.ScanPhaseFailed)

	if err := r.removeFinalizer(ctx, job, finalizerOmni); err != nil {
		return fmt.Errorf("remove job finalizer: %w", err)
	}

	return fmt.Errorf("%w on job %s/%s", errMissingPVCAnnotation, job.Namespace, job.Name)
}

// handleMissingSnapshot marks the scan as failed when orchestration job completes without snapshot annotation.
func (r *ScanReconciler) handleMissingSnapshot(ctx context.Context, scan *v1alpha1.Scan, job *batchv1.Job) error {
	key := types.NamespacedName{Namespace: scan.Namespace, Name: scan.Name}
	r.updateCondition(ctx, key, v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionSnapshotTaken,
		Status:  corev1.ConditionFalse,
		Reason:  "NoSnapshot",
		Message: "orchestration job completed but snapshot annotation is missing",
	})

	r.updatePhase(ctx, key, v1alpha1.ScanPhaseFailed)

	if err := r.removeFinalizer(ctx, job, finalizerOmni); err != nil {
		return fmt.Errorf("remove job finalizer: %w", err)
	}

	return fmt.Errorf("%w on job %s/%s", errMissingSnapshotAnnotation, job.Namespace, job.Name)
}

// handleScanFailure marks the scan as failed and cleans up resources when scan job fails.
func (r *ScanReconciler) handleScanFailure(ctx context.Context, scan *v1alpha1.Scan, job, parent *batchv1.Job) (ctrl.Result, error) {
	msg := fmt.Sprintf("scan job %s/%s failed", job.Namespace, job.Name)
	key := types.NamespacedName{Namespace: scan.Namespace, Name: scan.Name}
	cond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionScanJobFinished,
		Status:  corev1.ConditionFalse,
		Reason:  "Failed",
		Message: msg,
	}
	if _, err := r.updateCondition(ctx, key, cond); err != nil {
		return ctrl.Result{}, fmt.Errorf("update condition: %w", err)
	}

	if err := r.updatePhase(ctx, key, v1alpha1.ScanPhaseFailed); err != nil {
		return ctrl.Result{}, fmt.Errorf("update phase: %w", err)
	}

	if err := r.removeFinalizer(ctx, parent, finalizerOmni); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove orch job finalizer: %w", err)
	}

	if err := r.removeFinalizer(ctx, job, finalizerOmni); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove scan job finalizer: %w", err)
	}

	if err := r.cleanupResources(ctx, scan.Namespace, job.GetAnnotations()); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup resources: %w", err)
	}

	return ctrl.Result{}, errors.New(msg)
}

// cleanupResources deletes the volume snapshot and PVC created by the orchestration job.
func (r *ScanReconciler) cleanupResources(ctx context.Context, ns string, annotations map[string]string) error {
	snapName, ok := annotations[annotationSnapshot]
	if ok {
		snap := &volumesnapshotv1.VolumeSnapshot{}
		key := types.NamespacedName{Namespace: ns, Name: snapName}
		if err := r.Get(ctx, key, snap); err != nil {
			if !apierr.IsNotFound(err) {
				return fmt.Errorf("get snapshot: %w", err)
			}
			goto Next
		}
		if err := r.removeFinalizer(ctx, snap, finalizerSnapshot); err != nil {
			return fmt.Errorf("remove snapshot finalizer: %w", err)
		}
		if err := r.Delete(ctx, snap); err != nil && !apierr.IsNotFound(err) {
			return fmt.Errorf("delete snapshot: %w", err)
		}
	}

Next:
	pvcName, ok := annotations[annotationPVC]
	if ok {
		pvc := &corev1.PersistentVolumeClaim{}
		pvcKey := types.NamespacedName{Namespace: ns, Name: pvcName}
		if err := r.Get(ctx, pvcKey, pvc); err != nil {
			if !apierr.IsNotFound(err) {
				return fmt.Errorf("get pvc: %w", err)
			}
			return nil
		}
		if err := r.removeFinalizer(ctx, pvc, finalizerPVC); err != nil {
			return fmt.Errorf("remove pvc finalizer: %w", err)
		}
		if err := r.Delete(ctx, pvc); err != nil && !apierr.IsNotFound(err) {
			return fmt.Errorf("delete pvc: %w", err)
		}
	}

	return nil
}

// removeFinalizer removes the specified finalizer from an object.
func (r *ScanReconciler) removeFinalizer(ctx context.Context, obj client.Object, finalizer string) error {
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	if !ctrlutil.RemoveFinalizer(obj, finalizer) {
		return nil
	}
	if err := r.Patch(ctx, obj, patch); err != nil {
		if apierr.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}
