package sensor

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// WorkloadResolver resolves a pod (namespace, name) to its owning workload name
// and the image ref of its first container.
//
// Supported owner chains:
//   - Pod → ReplicaSet → Deployment  (returns Deployment name)
//   - Pod → StatefulSet              (returns StatefulSet name)
//
// Returns ("", imageRef, nil) for pod types not yet tracked:
// DaemonSet pods, Job pods, standalone pods.
type WorkloadResolver interface {
	ResolveWorkload(ctx context.Context, namespace, podName string) (workloadName, imageRef string, err error)
}

// DeploymentResolver is a backward-compat alias kept so existing callers outside
// this package do not break. New code should use WorkloadResolver.
type DeploymentResolver = WorkloadResolver

type k8sResolver struct{ client kubernetes.Interface }

// NewWorkloadResolver creates a resolver using the in-cluster ServiceAccount config.
// Only call this when --controller-url is set (K8s mode).
func NewWorkloadResolver() (WorkloadResolver, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}
	return &k8sResolver{client: c}, nil
}

// NewK8sResolver is a backward-compat alias for NewWorkloadResolver.
func NewK8sResolver() (WorkloadResolver, error) { return NewWorkloadResolver() }

// ResolveWorkload walks the pod's owner references to find its controlling workload.
//
// For Deployment-managed pods: Pod → ReplicaSet → Deployment.
// For StatefulSet-managed pods: Pod → StatefulSet (direct, no ReplicaSet).
//
// Also returns the image ref of the pod's first container (from Status when
// available, falling back to Spec).
func (r *k8sResolver) ResolveWorkload(ctx context.Context, namespace, podName string) (string, string, error) {
	pod, err := r.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("get pod %s/%s: %w", namespace, podName, err)
	}

	// Best-effort image ref: prefer Status (actual running image incl. digest)
	// then fall back to Spec (declared image).
	imageRef := ""
	if len(pod.Status.ContainerStatuses) > 0 {
		imageRef = pod.Status.ContainerStatuses[0].Image
	}
	if imageRef == "" && len(pod.Spec.Containers) > 0 {
		imageRef = pod.Spec.Containers[0].Image
	}

	var rsName string
	for _, ref := range pod.OwnerReferences {
		switch ref.Kind {
		case "ReplicaSet":
			rsName = ref.Name
		case "StatefulSet":
			// StatefulSet pods are owned directly — no ReplicaSet intermediary.
			return ref.Name, imageRef, nil
		}
	}

	// Deployment path: resolve ReplicaSet → Deployment.
	if rsName == "" {
		return "", imageRef, nil
	}
	rs, err := r.client.AppsV1().ReplicaSets(namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil {
		return "", imageRef, fmt.Errorf("get replicaset %s/%s: %w", namespace, rsName, err)
	}
	for _, ref := range rs.OwnerReferences {
		if ref.Kind == "Deployment" {
			return ref.Name, imageRef, nil
		}
	}
	return "", imageRef, nil
}

// ResolveDeployment is a backward-compat alias for ResolveWorkload.
func (r *k8sResolver) ResolveDeployment(ctx context.Context, namespace, podName string) (string, string, error) {
	return r.ResolveWorkload(ctx, namespace, podName)
}
