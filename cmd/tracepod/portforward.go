package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const controllerLabel = "app.kubernetes.io/name=tracepod-controller"

// Connect finds the first running controller pod in controllerNamespace, opens
// a port-forward to its port 8080, and returns the base URL to reach it plus a
// cleanup function that must be called when the caller is done.
func Connect(cfg *rest.Config, controllerNamespace string) (baseURL string, cleanup func(), err error) {
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("build k8s client: %w", err)
	}

	// Find a running controller pod.
	podList, err := client.CoreV1().Pods(controllerNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: controllerLabel,
	})
	if err != nil {
		return "", nil, fmt.Errorf("list controller pods in %q: %w", controllerNamespace, err)
	}
	var pod *corev1.Pod
	for i := range podList.Items {
		if podList.Items[i].Status.Phase == corev1.PodRunning {
			pod = &podList.Items[i]
			break
		}
	}
	if pod == nil {
		return "", nil, fmt.Errorf("no running controller pod found in namespace %q (label: %s)", controllerNamespace, controllerLabel)
	}

	// Build the port-forward URL.
	pfURL, err := url.Parse(fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/portforward",
		cfg.Host, pod.Namespace, pod.Name))
	if err != nil {
		return "", nil, fmt.Errorf("build portforward URL: %w", err)
	}

	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("build SPDY transport: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, pfURL)

	stopChan := make(chan struct{})
	readyChan := make(chan struct{})

	fw, err := portforward.New(dialer, []string{"0:8080"}, stopChan, readyChan, io.Discard, io.Discard)
	if err != nil {
		return "", nil, fmt.Errorf("create port-forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- fw.ForwardPorts() }()

	select {
	case <-readyChan:
		// tunnel is up
	case err := <-errCh:
		return "", nil, fmt.Errorf("port-forward failed: %w", err)
	}

	ports, err := fw.GetPorts()
	if err != nil || len(ports) == 0 {
		close(stopChan)
		return "", nil, fmt.Errorf("get forwarded port: %w", err)
	}

	localPort := ports[0].Local
	cleanup = func() { close(stopChan) }
	return fmt.Sprintf("http://localhost:%d", localPort), cleanup, nil
}
