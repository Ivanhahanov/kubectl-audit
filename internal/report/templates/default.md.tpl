# Kubernetes Security Audit Report

- **Generated:** {{ rfc3339 .GeneratedAt }}
- **Target:** {{ .Target }}
{{- if .ClusterVersion }}
- **Cluster version:** {{ .ClusterVersion }}
{{- end }}
- **Policies loaded:** {{ .PoliciesLoaded }}

## Table of Contents

- [Scope](#scope)
{{- if .DetectedComponents }}
- [Detected Components](#detected-components)
{{- end }}
- [Summary](#summary)
{{- range .Frameworks }}
- [{{ .Title }} Compliance](#compliance-{{ slug .ID }})
{{- end }}
{{- if .ConsolidatedSummary }}
- [Consolidated Compliance Summary](#consolidated-summary)
{{- end }}
{{- if .RBACModel }}
- [RBAC Role Model](#rbac-role-model)
{{- end }}
{{- if .FindingsByNamespace }}
- [Findings by Namespace{{ if not .NamespaceDetailed }} (index){{ end }}](#findings-by-namespace)
{{- end }}
{{- if ne .ReportView "namespace" }}
- [Findings](#findings)
{{- range .FindingsBySeverity }}
  - [{{ .Severity }} ({{ len .Findings }})](#findings-{{ slug (print .Severity) }})
{{- end }}
{{- end }}
{{- if .Suppressed }}
- [Suppressed Findings](#suppressed-findings)
{{- end }}

<a id="scope"></a>

## Scope

{{ if .Scope.OutOfScope -}}
Not covered by this scan:

{{ range .Scope.OutOfScope }}- **{{ .Title }}** — {{ .Reason }}
{{ end -}}
{{- else -}}
Full scope: no structural gaps detected — control-plane, RBAC, and NetworkPolicy objects were all
observed for this target.
{{- end }}
{{- if .Scope.Caveats }}
Checked, but with a lower-confidence caveat worth reading before trusting the result:

{{ range .Scope.Caveats }}- **{{ .Title }}** — {{ .Reason }}
{{ end -}}
{{- end }}
{{- if .DetectedComponents }}

<a id="detected-components"></a>

## Detected Components

Well-known third-party operators/CNIs this tool recognized in the scanned resources (see
`internal/thirdparty`). System components have a matching built-in PSS exception
(`internal/suppress/builtin-exclusions.yaml`) for their documented, unavoidable privileges;
Application components get no exception and are checked at full strength.

| Component | Category | Detected via | Helm-managed |
|---|---|---|---|
{{- range .DetectedComponents }}
| {{ escapeCell .Name }} | {{ .Category }} | {{ detectedVia . }} | {{ if .HelmManaged }}Yes{{ else }}No{{ end }} |
{{- end }}
{{- end }}

<a id="summary"></a>

## Summary

| Severity | Count |
|---|---|
{{- range .SeverityOrder }}
| {{ . }} | {{ index $.Summary . }} |
{{- end }}
| **Total** | **{{ .TotalFindings }}** |
{{- if .Suppressed }}
| **Suppressed** | **{{ len .Suppressed }}** (see [Suppressed Findings](#suppressed-findings)) |
{{- end }}
{{ range .Frameworks }}
<a id="compliance-{{ slug .ID }}"></a>

## {{ .Title }} Compliance (v{{ .Version }})

<details>
<summary>Full control list ({{ len .Results }} controls) — click to expand</summary>

| Control | Title | Section | Status | Findings | Related controls |
|---|---|---|---|---|---|
{{- range .Results }}
| {{ .Control.ID }} | {{ escapeCell .Control.Title }} | {{ escapeCell .Control.Section }} | {{ .Status }} | {{ if eq (print .Status) "FAIL" }}{{ len .Findings }}{{ end }} | {{ crossRefs .Control }} |
{{- end }}

</details>
{{- $notes := statusNotes . }}
{{- if $notes }}
<details>
<summary>Not Applicable / Not Implemented notes</summary>

{{ range $notes }}{{ . }}
{{ end -}}
</details>
{{- end }}
{{- $failing := failingControls . }}
{{- if $failing }}

### Failing controls — affected resources

Full detail (message, remediation) for each of these is in **Findings** below, grouped by check;
this just shows which resources make each control fail.
{{ range $failing }}
#### {{ .Control.ID }} — {{ escapeCell .Control.Title }}
{{ range .Findings }}- **[{{ .Severity }}]** {{ .Resource.String }} — `{{ .PolicyID }}`
{{ end }}{{ end -}}
{{- end }}
{{ end -}}
{{- if .ConsolidatedSummary }}
<a id="consolidated-summary"></a>

## Consolidated Compliance Summary

| Framework | Version | Pass | Fail | N/A | Not Implemented | Total |
|---|---|---|---|---|---|---|
{{- range .ConsolidatedSummary }}
| {{ .Title }} | {{ .Version }} | {{ .Pass }} | {{ .Fail }} | {{ .NotApplicable }} | {{ .NotImplemented }} | {{ .Total }} |
{{- end }}
{{ end -}}
{{- if .RBACModel }}
<a id="rbac-role-model"></a>

## RBAC Role Model

| Subject | Namespace | Bindings | Permissions | Risk Flags |
|---|---|---|---|---|
{{- range .RBACModel }}
| {{ .Subject.Kind }}/{{ escapeCell .Subject.Name }} | {{ orDash .Subject.Namespace }} | {{ escapeCell (join (bindingLabels .Bindings) "<br>") }} | {{ escapeCell (join .Permissions "<br>") }} | {{ escapeCell (join .RiskFlags "<br>") }} |
{{- end }}
{{ end }}
{{- if or .FindingsByNamespace .NamespaceDetailed }}
<a id="findings-by-namespace"></a>

{{ if .NamespaceDetailed }}## Findings by Namespace

{{ if not .FindingsByNamespace }}No findings.
{{ else }}Every finding, grouped by namespace and then by resource.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Cluster-scoped{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
#### {{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}
{{ range .Findings }}- **[{{ .Severity }}] `{{ .PolicyID }}`** — {{ .Message }}{{ if .Remediation }} _Remediation: {{ .Remediation }}_{{ end }}
{{ end }}{{ end }}{{ end }}{{ end }}
{{ else }}<details>
<summary><h2 style="display:inline">Findings by Namespace (index)</h2></summary>

One place per app/team to see what's affecting it, one line per finding — no message/remediation
text repeated here; look up the policy ID in **Findings** below for full detail on any of these.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Cluster-scoped{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
**{{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}**
{{ range .Findings }}- **[{{ .Severity }}]** `{{ .PolicyID }}`
{{ end }}{{ end }}{{ end }}

</details>
{{ end }}
{{ end }}
{{- if ne .ReportView "namespace" }}
<a id="findings"></a>

## Findings
{{ if not .Findings }}
No findings.
{{- else -}}
{{ range .FindingsBySeverity }}
<a id="findings-{{ slug (print .Severity) }}"></a>

### {{ .Severity }} ({{ len .Findings }})
{{ range .Checks }}
#### [{{ .PolicyID }}] {{ .Title }}

- **Category:** {{ .Category }}
{{- if .CIS }}
- **CIS:** {{ join .CIS ", " }}
{{- end }}
{{- if .Remediation }}
- **Remediation:** {{ .Remediation }}
{{- end }}
- **Affected resources ({{ len .Findings }}):**
{{ if .UniformMessage }}
  _{{ .UniformMessage }}_
{{ range .Rows }}{{ if .Repeat }}  - **{{ .Repeat.Kind }}/{{ escapeCell .Repeat.Name }}** — repeated identically in **{{ len .Repeat.Namespaces }} namespaces**: {{ join .Repeat.Namespaces ", " }}
{{ else }}  - {{ .Finding.Resource.String }}{{ if and .Finding.Source $.MultipleSources }} (`{{ .Finding.Source }}`){{ end }}
{{ end }}{{ end }}{{ else }}
{{ range .Findings }}  - **{{ .Resource.String }}**{{ if and .Source $.MultipleSources }} (`{{ .Source }}`){{ end }} — {{ .Message }}
{{ end }}{{ end }}
{{ end -}}
{{ end -}}
{{- end }}
{{- end }}
{{- if .Suppressed }}

<a id="suppressed-findings"></a>

<details>
<summary><h2 style="display:inline">Suppressed Findings ({{ len .Suppressed }})</h2></summary>

Matched an `exclusions` rule in `audit.yaml` — not counted in Summary and don't affect `--fail-on`.
{{ range .Suppressed }}
- **[{{ .Finding.Severity }}] `{{ .Finding.PolicyID }}`** {{ .Finding.Resource.String }} — _{{ .Reason }}_
{{- end }}

</details>
{{- end }}
