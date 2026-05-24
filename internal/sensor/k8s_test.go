package sensor

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newResolver(objs ...interface{}) *k8sResolver {
	client := fake.NewClientset()
	ctx := context.Background()
	for _, o := range objs {
		switch v := o.(type) {
		case corev1.Pod:
			_, _ = client.CoreV1().Pods(v.Namespace).Create(ctx, &v, metav1.CreateOptions{})
		case appsv1.ReplicaSet:
			_, _ = client.AppsV1().ReplicaSets(v.Namespace).Create(ctx, &v, metav1.CreateOptions{})
		case appsv1.StatefulSet:
			_, _ = client.AppsV1().StatefulSets(v.Namespace).Create(ctx, &v, metav1.CreateOptions{})
		}
	}
	return &k8sResolver{client: client}
}

// makePod creates a pod owned by a ReplicaSet (the standard Deployment path).
func makePod(ns, name, rsOwner string) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25-alpine"}}},
	}
	if rsOwner != "" {
		pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rsOwner}}
	}
	return pod
}

// makePodWithOwner creates a pod with an arbitrary owner kind (e.g. "StatefulSet").
func makePodWithOwner(ns, name, ownerKind, ownerName string) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "postgres:16-alpine"}}},
	}
	if ownerKind != "" {
		pod.OwnerReferences = []metav1.OwnerReference{{Kind: ownerKind, Name: ownerName}}
	}
	return pod
}

func makeRS(ns, name, depOwner string) appsv1.ReplicaSet {
	rs := appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	if depOwner != "" {
		rs.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: depOwner}}
	}
	return rs
}

func makeStatefulSet(ns, name string) appsv1.StatefulSet {
	return appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
}

// ── Deployment path tests ─────────────────────────────────────────────────────

func TestWorkloadResolver_Deployment_HappyPath(t *testing.T) {
	r := newResolver(
		makePod("default", "my-pod", "my-rs"),
		makeRS("default", "my-rs", "my-deploy"),
	)
	name, _, err := r.ResolveWorkload(context.Background(), "default", "my-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "my-deploy" {
		t.Errorf("want %q, got %q", "my-deploy", name)
	}
}

func TestWorkloadResolver_Deployment_ImageRef(t *testing.T) {
	pod := makePod("default", "my-pod", "my-rs")
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Image: "nginx:1.25-alpine@sha256:abc123"},
	}
	r := newResolver(pod, makeRS("default", "my-rs", "my-deploy"))
	_, imageRef, err := r.ResolveWorkload(context.Background(), "default", "my-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imageRef != "nginx:1.25-alpine@sha256:abc123" {
		t.Errorf("want image from Status, got %q", imageRef)
	}
}

func TestWorkloadResolver_PodHasNoOwner(t *testing.T) {
	r := newResolver(makePod("default", "standalone-pod", ""))
	name, _, err := r.ResolveWorkload(context.Background(), "default", "standalone-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Errorf("want empty workload name for standalone pod, got %q", name)
	}
}

func TestWorkloadResolver_RSHasNoDeploymentOwner(t *testing.T) {
	r := newResolver(
		makePod("default", "my-pod", "standalone-rs"),
		makeRS("default", "standalone-rs", ""),
	)
	name, _, err := r.ResolveWorkload(context.Background(), "default", "my-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Errorf("want empty workload name for standalone RS, got %q", name)
	}
}

func TestWorkloadResolver_PodNotFound(t *testing.T) {
	r := newResolver()
	_, _, err := r.ResolveWorkload(context.Background(), "default", "missing-pod")
	if err == nil {
		t.Fatal("expected error for missing pod, got nil")
	}
}

func TestWorkloadResolver_RSNotFound(t *testing.T) {
	r := newResolver(makePod("default", "my-pod", "ghost-rs"))
	_, _, err := r.ResolveWorkload(context.Background(), "default", "my-pod")
	if err == nil {
		t.Fatal("expected error for missing replicaset, got nil")
	}
}

// ── StatefulSet path tests ────────────────────────────────────────────────────

func TestWorkloadResolver_StatefulSet_HappyPath(t *testing.T) {
	r := newResolver(
		makePodWithOwner("acme-web", "postgres-0", "StatefulSet", "postgres"),
		makeStatefulSet("acme-web", "postgres"),
	)
	name, _, err := r.ResolveWorkload(context.Background(), "acme-web", "postgres-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "postgres" {
		t.Errorf("want %q, got %q", "postgres", name)
	}
}

func TestWorkloadResolver_StatefulSet_ImageRef(t *testing.T) {
	pod := makePodWithOwner("acme-web", "postgres-0", "StatefulSet", "postgres")
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Image: "postgres:16-alpine"},
	}
	r := newResolver(pod, makeStatefulSet("acme-web", "postgres"))
	name, imageRef, err := r.ResolveWorkload(context.Background(), "acme-web", "postgres-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "postgres" {
		t.Errorf("want workload name %q, got %q", "postgres", name)
	}
	if imageRef != "postgres:16-alpine" {
		t.Errorf("want image %q, got %q", "postgres:16-alpine", imageRef)
	}
}

func TestWorkloadResolver_StatefulSet_MultiReplica(t *testing.T) {
	// StatefulSet with multiple replicas — each pod should resolve to the same StatefulSet name.
	r := newResolver(
		makePodWithOwner("ns", "redis-0", "StatefulSet", "redis"),
		makePodWithOwner("ns", "redis-1", "StatefulSet", "redis"),
		makeStatefulSet("ns", "redis"),
	)
	for _, podName := range []string{"redis-0", "redis-1"} {
		name, _, err := r.ResolveWorkload(context.Background(), "ns", podName)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", podName, err)
		}
		if name != "redis" {
			t.Errorf("%s: want %q, got %q", podName, "redis", name)
		}
	}
}

func TestWorkloadResolver_StatefulSet_DoesNotLookUpRS(t *testing.T) {
	// StatefulSet pods must NOT trigger a ReplicaSet lookup — the StatefulSet
	// name is returned directly. No RS exists in this fake cluster.
	r := newResolver(
		makePodWithOwner("ns", "kafka-0", "StatefulSet", "kafka"),
		// intentionally no makeStatefulSet — the resolver does not GET it
	)
	name, _, err := r.ResolveWorkload(context.Background(), "ns", "kafka-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "kafka" {
		t.Errorf("want %q, got %q", "kafka", name)
	}
}

// ── Backward-compat alias tests ───────────────────────────────────────────────

func TestWorkloadResolver_BackwardCompatAlias(t *testing.T) {
	// ResolveDeployment must still work identically (used by existing callers).
	r := newResolver(
		makePod("default", "my-pod", "my-rs"),
		makeRS("default", "my-rs", "my-deploy"),
	)
	dep, _, err := r.ResolveDeployment(context.Background(), "default", "my-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dep != "my-deploy" {
		t.Errorf("want %q, got %q", "my-deploy", dep)
	}
}
