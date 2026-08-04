# Kubernetes Security Audit Report

- **Generated:** {{ rfc3339 .GeneratedAt }}
- **Target:** {{ .Target }}
{{- if .ClusterVersion }}
- **Cluster version:** {{ .ClusterVersion }}
{{- end }}
- **Policies loaded:** {{ .PoliciesLoaded }}

## Scope

{{ if .Scope.OutOfScope -}}
Not covered by this scan:

{{ range .Scope.OutOfScope }}- **{{ .Title }}** — {{ .Reason }}
{{ end -}}
{{- else -}}
Full scope: no structural gaps detected — control-plane, RBAC, and NetworkPolicy objects were all
observed for this target.
{{- end }}

## Summary

| Severity | Count |
|---|---|
{{- range .SeverityOrder }}
| {{ . }} | {{ index $.Summary . }} |
{{- end }}
| **Total** | **{{ .TotalFindings }}** |
{{ range .Frameworks }}
## {{ .Title }} Compliance (v{{ .Version }})

| Control | Title | Section | Status | Findings | Related controls |
|---|---|---|---|---|---|
{{- range .Results }}
| {{ .Control.ID }} | {{ escapeCell .Control.Title }} | {{ escapeCell .Control.Section }} | {{ .Status }} | {{ if eq (print .Status) "FAIL" }}{{ len .Findings }}{{ end }} | {{ crossRefs .Control }} |
{{- end }}
{{- $notes := statusNotes . }}
{{- if $notes }}
{{ range $notes }}{{ . }}
{{ end -}}
{{- end }}
{{- $failing := failingControls . }}
{{- if $failing }}
### Failing controls — affected resources

Full detail (message, remediation) for each of these is in **Findings by Namespace** and
**Findings** below; this just shows which resources make each control fail.
{{ range $failing }}
#### {{ .Control.ID }} — {{ escapeCell .Control.Title }}
{{ range .Findings }}- **[{{ .Severity }}]** {{ .Resource.String }} — `{{ .PolicyID }}`
{{ end }}{{ end -}}
{{- end }}
{{ end -}}
{{- if .ConsolidatedSummary }}
## Consolidated Compliance Summary

| Framework | Version | Pass | Fail | N/A | Not Implemented | Total |
|---|---|---|---|---|---|---|
{{- range .ConsolidatedSummary }}
| {{ .Title }} | {{ .Version }} | {{ .Pass }} | {{ .Fail }} | {{ .NotApplicable }} | {{ .NotImplemented }} | {{ .Total }} |
{{- end }}
{{ end -}}
{{- if .RBACModel }}
## RBAC Role Model

| Subject | Namespace | Bindings | Permissions | Risk Flags |
|---|---|---|---|---|
{{- range .RBACModel }}
| {{ .Subject.Kind }}/{{ escapeCell .Subject.Name }} | {{ orDash .Subject.Namespace }} | {{ escapeCell (join (bindingLabels .Bindings) "<br>") }} | {{ escapeCell (join .Permissions "<br>") }} | {{ escapeCell (join .RiskFlags "<br>") }} |
{{- end }}
{{ end }}
{{- if .FindingsByNamespace }}
## Findings by Namespace

One place per app/team to see everything affecting it, instead of hunting across the
compliance sections above. Severity-first, cluster-wide view is in **Findings** below.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Cluster-scoped{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
#### {{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}
{{ range .Findings }}- **[{{ .Severity }}] `{{ .PolicyID }}`** — {{ .Message }}{{ if .Remediation }} _Remediation: {{ .Remediation }}_{{ end }}
{{ end }}{{ end }}{{ end }}
{{ end }}
## Findings
{{ if not .Findings }}
No findings.
{{- else -}}
{{ range .FindingsBySeverity }}
### {{ .Severity }}
{{ range .Findings }}
#### [{{ .PolicyID }}] {{ .Resource.String }}

- **Category:** {{ .Category }}
{{- if .CIS }}
- **CIS:** {{ join .CIS ", " }}
{{- end }}
{{- if .Source }}
- **Source:** {{ .Source }}
{{- end }}
- **Message:** {{ .Message }}
{{- if .Remediation }}
- **Remediation:** {{ .Remediation }}
{{- end }}
{{ end -}}
{{ end -}}
{{- end }}
