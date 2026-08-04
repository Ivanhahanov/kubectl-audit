// Package k8supdates makes the one network call this tool ever performs
// beyond the target cluster itself: an opt-in (--check-updates), live
// lookup against endoflife.date's Kubernetes release-cycle API to check
// whether the detected cluster version has a newer patch release available
// (potential missed security fixes) or has reached real end-of-life —
// replacing internal/k8sversion's hardcoded version-distance approximation
// with actual release/EOL data when a network call is acceptable.
//
// Off by default: this tool is otherwise fully offline (every other check
// only reads the target cluster/manifests), which matters for air-gapped or
// otherwise network-restricted environments a security audit tool commonly
// runs in. A fetch failure (network unavailable, API down, rate-limited)
// only produces a warning, never aborts the scan — internal/k8sversion's
// approximation still runs unconditionally as a fallback baseline signal.
package k8supdates

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sversion"
)

// DefaultAPIURL is endoflife.date's Kubernetes release-cycle endpoint.
const DefaultAPIURL = "https://endoflife.date/api/v1/products/kubernetes"

const (
	CheckIDEOL           = "k8supdates.end-of-life"
	CheckIDEOAS          = "k8supdates.end-of-active-support"
	CheckIDPatchOutdated = "k8supdates.patch-available"
	CheckIDMinorOutdated = "k8supdates.newer-minor-available"
)

type apiResponse struct {
	Result struct {
		Releases []release `json:"releases"`
	} `json:"result"`
}

type release struct {
	Name         string `json:"name"` // e.g. "1.35"
	ReleaseDate  string `json:"releaseDate"`
	IsEoas       bool   `json:"isEoas"`
	EoasFrom     string `json:"eoasFrom"`
	IsEol        bool   `json:"isEol"`
	EolFrom      string `json:"eolFrom"`
	IsMaintained bool   `json:"isMaintained"`
	Latest       struct {
		Name string `json:"name"` // e.g. "1.35.4"
		Date string `json:"date"`
		Link string `json:"link"`
	} `json:"latest"`
}

// Client fetches and checks; the zero value uses DefaultAPIURL and a 10s
// timeout http.Client — override APIURL/HTTPClient in tests.
type Client struct {
	APIURL     string
	HTTPClient *http.Client
}

// Check fetches current Kubernetes release-cycle data and compares the
// detected cluster version against it. detectedVersion is the raw
// client-go discovery GitVersion (e.g. "v1.27.16"); an empty or
// unparseable value returns no findings and no error (nothing to check —
// e.g. a static-manifest-only scan).
func (c Client) Check(ctx context.Context, detectedVersion, source string) ([]findings.Finding, error) {
	major, minor, ok := k8sversion.Parse(detectedVersion)
	if !ok {
		return nil, nil
	}

	releases, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}

	cycleName := fmt.Sprintf("%d.%d", major, minor)
	var matched *release
	newestMajor, newestMinor := 0, 0
	var newestCycle string
	for i := range releases {
		rMajor, rMinor, rOK := k8sversion.Parse(releases[i].Name)
		if !rOK {
			continue
		}
		if releases[i].Name == cycleName {
			matched = &releases[i]
		}
		if rMajor > newestMajor || (rMajor == newestMajor && rMinor > newestMinor) {
			newestMajor, newestMinor = rMajor, rMinor
			newestCycle = releases[i].Name
		}
	}

	ref := findings.ResourceRef{Kind: "Cluster", Name: detectedVersion}
	var out []findings.Finding

	if matched == nil {
		// Not in the (currently ~22-cycle) list at all: older than
		// anything endoflife.date still tracks for Kubernetes — an even
		// stronger signal than IsEol on a tracked-but-EOL cycle.
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDEOL, ref),
			PolicyID: CheckIDEOL,
			Title:    "Cluster is running a Kubernetes version end-of-life data doesn't cover",
			Severity: findings.SeverityCritical,
			Category: "patch-lifecycle",
			Resource: ref,
			Message: fmt.Sprintf("Detected Kubernetes %s (cycle %s), which isn't among the %d release cycles endoflife.date currently tracks for Kubernetes — it's older than any of them, meaning it's been end-of-life for upstream security patches for a long time.",
				detectedVersion, cycleName, len(releases)),
			Remediation: "Plan an urgent upgrade path; this version has had no upstream security patches for an extended period.",
			Source:      source,
		})
		return out, nil
	}

	if matched.IsEol {
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDEOL, ref),
			PolicyID: CheckIDEOL,
			Title:    "Cluster is running an end-of-life Kubernetes version",
			Severity: findings.SeverityCritical,
			Category: "patch-lifecycle",
			Resource: ref,
			Message: fmt.Sprintf("Detected Kubernetes %s (cycle %s), which reached end-of-life on %s per endoflife.date — no more upstream security patches.",
				detectedVersion, cycleName, orUnknown(matched.EolFrom)),
			Remediation: "Plan an upgrade path to a maintained minor version, or confirm this cluster is on a vendor's paid extended-support track that still backports fixes.",
			Source:      source,
		})
	} else if matched.IsEoas || !matched.IsMaintained {
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDEOAS, ref),
			PolicyID: CheckIDEOAS,
			Title:    "Cluster's Kubernetes version is past active support (security-fixes-only or unmaintained)",
			Severity: findings.SeverityMedium,
			Category: "patch-lifecycle",
			Resource: ref,
			Message: fmt.Sprintf("Detected Kubernetes %s (cycle %s) entered end-of-active-support on %s per endoflife.date — active development/feature backports have stopped; verify it's still receiving the security-only patches it's entitled to.",
				detectedVersion, cycleName, orUnknown(matched.EoasFrom)),
			Remediation: "Plan an upgrade to a fully-maintained minor version.",
			Source:      source,
		})
	}

	if matched.Latest.Name != "" && matched.Latest.Name != trimV(detectedVersion) {
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDPatchOutdated, ref),
			PolicyID: CheckIDPatchOutdated,
			Title:    "Newer patch release available for this Kubernetes minor version",
			Severity: findings.SeverityMedium,
			Category: "patch-lifecycle",
			Resource: ref,
			Message: fmt.Sprintf("Detected Kubernetes %s; %s (released %s) is the latest patch release in the %s cycle per endoflife.date — a patch release can include backported security fixes.",
				detectedVersion, matched.Latest.Name, orUnknown(matched.Latest.Date), cycleName),
			Remediation: fmt.Sprintf("Upgrade to %s (or the current latest patch in the %s cycle) to pick up any backported security fixes.", matched.Latest.Name, cycleName),
			Source:      source,
		})
	}

	if newestCycle != "" && newestCycle != cycleName && (newestMajor > major || newestMinor > minor) {
		out = append(out, findings.Finding{
			ID:       findings.NewID(CheckIDMinorOutdated, ref),
			PolicyID: CheckIDMinorOutdated,
			Title:    "Newer Kubernetes minor version cycle available",
			Severity: findings.SeverityLow,
			Category: "patch-lifecycle",
			Resource: ref,
			Message: fmt.Sprintf("Detected Kubernetes %s (cycle %s); %s is the newest release cycle per endoflife.date.",
				detectedVersion, cycleName, newestCycle),
			Remediation: "Not urgent by itself (unlike the findings above, being behind the newest minor isn't a security issue on its own) — factor into normal upgrade planning.",
			Source:      source,
		})
	}

	return out, nil
}

func (c Client) fetch(ctx context.Context) ([]release, error) {
	url := c.APIURL
	if url == "" {
		url = DefaultAPIURL
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request to %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	var out apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing response from %s: %w", url, err)
	}
	return out.Result.Releases, nil
}

func trimV(gitVersion string) string {
	v := gitVersion
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	// Strip any vendor/build suffix (e.g. "1.27.16-eks-abc1234") so it can
	// be compared against endoflife.date's plain "major.minor.patch".
	for i, c := range v {
		if c != '.' && (c < '0' || c > '9') {
			return v[:i]
		}
	}
	return v
}

func orUnknown(s string) string {
	if s == "" {
		return "an unspecified date"
	}
	return s
}
