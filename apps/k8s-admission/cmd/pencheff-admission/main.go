// SPDX-License-Identifier: MIT
//
// pencheff-admission — Kubernetes ValidatingAdmissionWebhook that
// blocks pods whose container images carry critical-severity
// unfixed CVEs reported by the Pencheff API.
//
// Phase 4.1 of the IP-clean expansion plan. Built with controller-
// runtime's deps minimised to k8s.io/api + k8s.io/apimachinery only —
// no full controller-runtime import — so the binary stays small.
//
// The policy decision lives in internal/policy.Decide(); this file
// is just the HTTP plumbing + AdmissionReview marshalling.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/BalaSriharsha-Ch/pencheff/apps/k8s-admission/internal/policy"
)

var (
	addr        = flag.String("addr", ":8443", "HTTPS listen address")
	certFile    = flag.String("tls-cert", "/etc/pencheff/tls/tls.crt", "TLS certificate path")
	keyFile     = flag.String("tls-key", "/etc/pencheff/tls/tls.key", "TLS private key path")
	pencheffURL = flag.String("pencheff-api", "http://pencheff-api/api", "Pencheff API base URL")
	apiToken    = flag.String("api-token", "", "Pencheff API bearer token (env PENCHEFF_API_TOKEN takes precedence)")
	failOpen    = flag.Bool("fail-open", false, "Allow pods through if the Pencheff API is unreachable (default: fail-closed)")
)

func main() {
	flag.Parse()
	if t := os.Getenv("PENCHEFF_API_TOKEN"); t != "" {
		*apiToken = t
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/validate", validate)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("pencheff-admission listening on %s (api=%s, fail-open=%t)",
		*addr, *pencheffURL, *failOpen)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// validate is the AdmissionReview ↔ AdmissionResponse handler.
//
// Standard webhook contract:
//
//	POST /validate
//	    body: AdmissionReview (apiVersion=admission.k8s.io/v1)
//	response 200 with AdmissionReview echoing the request UID +
//	    a populated `response.allowed` + optional `response.result`.
func validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp := decide(review.Request)
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}
	if review.Request != nil {
		out.Response.UID = review.Request.UID
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func decide(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	if req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied(req, "could not decode pod object: "+err.Error())
	}

	images := podImages(&pod)
	verdict, err := policy.Decide(policy.Inputs{
		Images:      images,
		PencheffAPI: *pencheffURL,
		APIToken:    *apiToken,
	})
	if err != nil {
		// Fail-open is opt-in; default is fail-closed so an outage in
		// the Pencheff API doesn't quietly let critical-CVE images land.
		if *failOpen {
			log.Printf("pencheff API unreachable (%v); fail-open allowing %s/%s",
				err, pod.Namespace, pod.Name)
			return &admissionv1.AdmissionResponse{
				Allowed: true,
				Warnings: []string{
					"Pencheff admission webhook could not reach the Pencheff API; " +
						"--fail-open=true allowed pod through anyway.",
				},
			}
		}
		return denied(req, "Pencheff admission webhook is fail-closed and could not reach the Pencheff API: "+err.Error())
	}

	if !verdict.Allow {
		return denied(req, verdict.Reason)
	}
	return &admissionv1.AdmissionResponse{Allowed: true}
}

func podImages(pod *corev1.Pod) []string {
	out := make([]string, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	for _, c := range pod.Spec.InitContainers {
		out = append(out, c.Image)
	}
	for _, c := range pod.Spec.Containers {
		out = append(out, c.Image)
	}
	return out
}

func denied(req *admissionv1.AdmissionRequest, reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: "denied by Pencheff: " + reason,
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		},
	}
}
