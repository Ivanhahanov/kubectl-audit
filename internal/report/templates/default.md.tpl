# Kubernetes Security Audit Report

- **Generated:** {{ rfc3339 .GeneratedAt }}
- **Target:** {{ .Target }}
{{- if .ClusterVersion }}
- **Cluster version:** {{ .ClusterVersion }}
{{- end }}
- **Policies loaded:** {{ .PoliciesLoaded }}

## Table of Contents

- [Scope](#scope)
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
- [Findings by Namespace (index)](#findings-by-namespace)
{{- end }}
- [Findings](#findings)
{{- range .FindingsBySeverity }}
  - [{{ .Severity }} ({{ len .Findings }})](#findings-{{ slug (print .Severity) }})
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

<a id="summary"></a>

## Summary

| Severity | Count |
|---|---|
{{- range .SeverityOrder }}
| {{ . }} | {{ index $.Summary . }} |
{{- end }}
| **Total** | **{{ .TotalFindings }}** |
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

{{ end -}}
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
{{- if .FindingsByNamespace }}
<a id="findings-by-namespace"></a>

<details>
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
{{ range .Findings }}  - {{ .Resource.String }}{{ if .Source }} (`{{ .Source }}`){{ end }}
{{ end }}{{ else }}
{{ range .Findings }}  - **{{ .Resource.String }}**{{ if .Source }} (`{{ .Source }}`){{ end }} — {{ .Message }}
{{ end }}{{ end }}
{{ end -}}
{{ end -}}
{{- end }}
