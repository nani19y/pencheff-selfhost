// SPDX-License-Identifier: MIT
//
// Package policy holds the decide-or-deny logic the admission webhook
// applies to each candidate pod.
//
// The current implementation queries the Pencheff API for each image
// in the pod and rejects if any image has unfixed critical-severity
// findings. The full surface (per-namespace policies, severity
// floors, exception annotations) is left to follow-up work — the
// shape here is the minimum viable gate.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Inputs is the request the admission webhook hands to Decide().
type Inputs struct {
	Images      []string
	PencheffAPI string
	APIToken    string
}

// Verdict is the policy result.
type Verdict struct {
	Allow  bool
	Reason string // populated when Allow == false
}

// imageVerdict is the Pencheff API response shape (as documented by
// the registry-scan endpoint added in Phase 4.1).
type imageVerdict struct {
	Image    string `json:"image"`
	Findings []struct {
		Severity string `json:"severity"`
		CVE      string `json:"cve"`
		Title    string `json:"title"`
		Fixed    bool   `json:"fixed"`
	} `json:"findings"`
}

// AnnotationOptOut lets a pod author bypass the gate by setting:
//
//	annotations:
//	  pencheff.io/admission-bypass: "<reason>"
//
// The annotation value is recorded in the warning so the audit trail
// shows who bypassed and why. Bypass is allowed by default; cluster
// operators who want to forbid it can set --bypass-disabled at the
// webhook command line (not yet wired — Phase 4 follow-up).
const AnnotationOptOut = "pencheff.io/admission-bypass"

// Decide is the synchronous policy gate.
func Decide(in Inputs) (Verdict, error) {
	if len(in.Images) == 0 {
		return Verdict{Allow: true}, nil
	}
	if in.PencheffAPI == "" {
		return Verdict{Allow: true}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, img := range in.Images {
		v, err := fetchImageVerdict(ctx, in.PencheffAPI, in.APIToken, img)
		if err != nil {
			return Verdict{}, fmt.Errorf("query %q: %w", img, err)
		}
		for _, f := range v.Findings {
			if !f.Fixed && strings.EqualFold(f.Severity, "critical") {
				return Verdict{
					Allow: false,
					Reason: fmt.Sprintf(
						"image %q has unfixed CRITICAL %s (%s); upgrade or annotate %s on the pod to bypass.",
						img, f.CVE, f.Title, AnnotationOptOut,
					),
				}, nil
			}
		}
	}
	return Verdict{Allow: true}, nil
}

func fetchImageVerdict(ctx context.Context, base, token, image string) (*imageVerdict, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/registries/image-verdict")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("image", image)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// No scan on file for this image — treat as unknown, allow.
		// Cluster operators who want stricter behaviour can run a
		// pre-deploy registry scan + change the policy.
		return &imageVerdict{Image: image}, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(body))
	}
	var out imageVerdict
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
