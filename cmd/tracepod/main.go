// Command tracepod is the user-facing CLI for the TracePod profiling system.
// It transparently port-forwards to the controller running in your Kubernetes
// cluster and provides subcommands to list, retrieve, and stop profiling sessions.
//
// Usage:
//
//	tracepod [--kubeconfig <path>] [--controller-namespace <ns>] <command>
//
// Commands:
//
//	profile list  [--namespace <ns>]
//	profile get   --namespace <ns> --deployment <name> [--output <file>]
//	profile stop  --namespace <ns> --deployment <name>
//	version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	kubeconfig := flag.String("kubeconfig", defaultKubeconfig(), "path to kubeconfig file")
	ctrlNS := flag.String("controller-namespace", "tracepod", "namespace where the TracePod controller is deployed")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: tracepod [--kubeconfig <path>] [--controller-namespace <ns>] <command>\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  profile list  [--namespace <ns>]\n")
		fmt.Fprintf(os.Stderr, "  profile get   --namespace <ns> --deployment <name> [--output <file>]\n")
		fmt.Fprintf(os.Stderr, "  profile stop  --namespace <ns> --deployment <name>\n")
		fmt.Fprintf(os.Stderr, "  version\n")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	switch args[0] {
	case "profile":
		runProfile(args[1:], *kubeconfig, *ctrlNS)
	case "version":
		fmt.Printf("tracepod %s (%s)\n", version, commit)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		flag.Usage()
		os.Exit(1)
	}
}

func runProfile(args []string, kubeconfig, ctrlNS string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: tracepod profile <list|get|stop>\n")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		runList(args[1:], kubeconfig, ctrlNS)
	case "get":
		runGet(args[1:], kubeconfig, ctrlNS)
	case "stop":
		runStop(args[1:], kubeconfig, ctrlNS)
	default:
		fmt.Fprintf(os.Stderr, "unknown profile subcommand %q\n", args[0])
		os.Exit(1)
	}
}

func runList(args []string, kubeconfig, ctrlNS string) {
	fs := flag.NewFlagSet("profile list", flag.ExitOnError)
	ns := fs.String("namespace", "", "filter by namespace (default: all)")
	fs.Parse(args) //nolint:errcheck

	baseURL, cleanup, err := connect(kubeconfig, ctrlNS)
	if err != nil {
		fatal("connect to controller: %v", err)
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sessions, err := ListProfiles(ctx, baseURL, *ns)
	if err != nil {
		fatal("list profiles: %v", err)
	}
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no profiling sessions found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAMESPACE\tDEPLOYMENT\tSTATUS\tFILES\tSTARTED AT")
	for _, s := range sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			s.Namespace, s.Deployment, s.Status, s.FileCount,
			s.StartedAt.Format(time.RFC3339))
	}
	w.Flush()
}

func runGet(args []string, kubeconfig, ctrlNS string) {
	fs := flag.NewFlagSet("profile get", flag.ExitOnError)
	ns := fs.String("namespace", "", "namespace of the deployment (required)")
	dep := fs.String("deployment", "", "deployment name (required)")
	output := fs.String("output", "", "write manifest JSON to this file instead of stdout")
	fs.Parse(args) //nolint:errcheck

	if *ns == "" || *dep == "" {
		fmt.Fprintf(os.Stderr, "Usage: tracepod profile get --namespace <ns> --deployment <name> [--output <file>]\n")
		os.Exit(1)
	}

	baseURL, cleanup, err := connect(kubeconfig, ctrlNS)
	if err != nil {
		fatal("connect to controller: %v", err)
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	data, err := GetProfile(ctx, baseURL, *ns, *dep)
	if err != nil {
		fatal("get profile: %v", err)
	}

	if *output == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fatal("write output file: %v", err)
	}
	fmt.Fprintf(os.Stderr, "manifest written to %s\n", *output)
}

func runStop(args []string, kubeconfig, ctrlNS string) {
	fs := flag.NewFlagSet("profile stop", flag.ExitOnError)
	ns := fs.String("namespace", "", "namespace of the deployment (required)")
	dep := fs.String("deployment", "", "deployment name (required)")
	fs.Parse(args) //nolint:errcheck

	if *ns == "" || *dep == "" {
		fmt.Fprintf(os.Stderr, "Usage: tracepod profile stop --namespace <ns> --deployment <name>\n")
		os.Exit(1)
	}

	baseURL, cleanup, err := connect(kubeconfig, ctrlNS)
	if err != nil {
		fatal("connect to controller: %v", err)
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := StopProfile(ctx, baseURL, *ns, *dep); err != nil {
		fatal("stop profile: %v", err)
	}
	fmt.Fprintf(os.Stderr, "profiling stopped for %s/%s\n", *ns, *dep)
}

// connect loads the kubeconfig and calls Connect to establish a port-forward.
func connect(kubeconfigPath, ctrlNS string) (string, func(), error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return "", nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfigPath, err)
	}
	return Connect(cfg, ctrlNS)
}

// defaultKubeconfig returns $KUBECONFIG if set, else ~/.kube/config.
func defaultKubeconfig() string {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return kc
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tracepod: "+format+"\n", args...)
	os.Exit(1)
}
