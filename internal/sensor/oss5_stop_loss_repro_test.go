package sensor

// OSS-5 Phase-1 reproduction — StopContainer generation loss.
//
// Boundary under test: A (observed-but-never-sent, OSS/sensor).
//
// cmd/sensor/main.go onContainerStop gates the final POST of a container's
// profile on a LIVE Kubernetes lookup performed at StopContainer time:
//
//	dep, imageRef, err := r.resolver.ResolveWorkload(ctx, pod.Namespace, pod.Name)
//	if err != nil { ...; return }          // <-- generation dropped, no POST
//	if dep == ""  { ...; return }          // <-- generation dropped, no POST
//
// ResolveWorkload (internal/sensor/k8s.go) walks Pod -> ReplicaSet -> Deployment
// with three live API GETs. StopContainer fires *after* the container process
// exits — i.e. during pod delete / scale-to-0 / rolling update, exactly when the
// pod and/or its ReplicaSet are being garbage-collected. If any GET 404s (or the
// owner chain is already broken), the resolve errors or yields dep=="" and the
// fully-observed final generation is silently dropped before it is ever sent.
//
// Because the deployment owner is resolved lazily at stop and never cached at
// start (contrast: pod namespace/name IS cached at CreateContainer), a single
// transient lookup failure at the worst possible moment = permanent loss of the
// generation. The controller's ingest is additive/monotone, so a generation that
// is never POSTed simply never exists in container_coverage or profile_events —
// matching WP0-F's "pods never reached container_coverage" symptom.
//
// This test drives the REAL k8sResolver against a fake clientset to prove the
// gate fails under GC. It asserts the loss directly; it does not assert a fix.
//
// One-command repro:  go test ./internal/sensor/ -run OSS5StopLoss -v

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// postGate mirrors cmd/sensor/main.go onContainerStop's decision: a profile is
// POSTed to the controller only when ResolveWorkload succeeds AND returns a
// non-empty deployment owner. Returns false when the generation is dropped.
func postGate(r *k8sResolver, ns, pod string) (posted bool, reason string) {
	dep, _, err := r.ResolveWorkload(context.Background(), ns, pod)
	if err != nil {
		return false, "resolve error: " + err.Error()
	}
	if dep == "" {
		return false, "no deployment owner"
	}
	return true, "posted to " + dep
}

func TestOSS5StopLoss_PodPresent_Posts(t *testing.T) {
	// Control: pod + ReplicaSet still present at stop. The generation lands.
	r := newResolver(
		makePod("ns1", "web-abc", "web-rs"),
		makeRS("ns1", "web-rs", "web"),
	)
	posted, reason := postGate(r, "ns1", "web-abc")
	if !posted {
		t.Fatalf("control case must POST, but generation was dropped: %s", reason)
	}
	t.Logf("control: %s", reason)
}

func TestOSS5StopLoss_PodGCRace_DropsGeneration(t *testing.T) {
	// Pod delete / scale-to-0: the pod object is GC'd before StopContainer's
	// live lookup runs. ResolveWorkload 404s -> POST gate fails -> the
	// fully-observed final generation is lost before it is ever sent.
	r := newResolver(
		makePod("ns1", "web-abc", "web-rs"),
		makeRS("ns1", "web-rs", "web"),
	)
	// Simulate the GC that races StopContainer.
	if err := r.client.CoreV1().Pods("ns1").Delete(context.Background(), "web-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("setup: delete pod: %v", err)
	}

	posted, reason := postGate(r, "ns1", "web-abc")
	if posted {
		t.Fatalf("expected generation loss under pod GC, but it POSTed: %s", reason)
	}
	t.Logf("REPRODUCED loss (pod GC): %s", reason)
}

func TestOSS5StopLoss_ReplicaSetGCRace_DropsGeneration(t *testing.T) {
	// Scale-to-0 / rolling update: the pod still exists (Terminating) but its
	// ReplicaSet has already been reaped. The Pod->RS->Deployment walk breaks at
	// the RS GET -> POST gate fails -> generation lost.
	r := newResolver(
		makePod("ns1", "web-abc", "web-rs"),
		makeRS("ns1", "web-rs", "web"),
	)
	if err := r.client.AppsV1().ReplicaSets("ns1").Delete(context.Background(), "web-rs", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("setup: delete replicaset: %v", err)
	}

	posted, reason := postGate(r, "ns1", "web-abc")
	if posted {
		t.Fatalf("expected generation loss under RS GC, but it POSTed: %s", reason)
	}
	t.Logf("REPRODUCED loss (ReplicaSet GC): %s", reason)
}
