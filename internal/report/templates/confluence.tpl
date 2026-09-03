h1. Kubernetes Security Audit Report

* *Generated:* {{ rfc3339 .GeneratedAt }}
* *Target:* {{ .Target }}
{{- if .ClusterVersion }}
* *Cluster version:* {{ .ClusterVersion }}
{{- end }}
* *Policies loaded:* {{ .PoliciesLoaded }}

{toc:maxLevel=3}

h2. Scope

{{ if .Scope.OutOfScope -}}
Not covered by this scan:

{{ range .Scope.OutOfScope }}* *{{ escapeCell .Title }}* — {{ escapeCell .Reason }}
{{ end -}}
{{- else -}}
Full scope: no structural gaps detected — control-plane, RBAC, and NetworkPolicy objects were all
observed for this target.
{{- end }}
{{- if .Scope.Caveats }}
Checked, but with a lower-confidence caveat worth reading before trusting the result:

{{ range .Scope.Caveats }}* *{{ escapeCell .Title }}* — {{ escapeCell .Reason }}
{{ end -}}
{{- end }}
{{- if .DetectedComponents }}

h2. Detected Components

Well-known third-party operators/CNIs this tool recognized in the scanned resources (see
{{"{{"}}internal/thirdparty{{"}}"}}). System components have a matching built-in PSS exception
({{"{{"}}internal/suppress/builtin-exclusions.yaml{{"}}"}}) for their documented, unavoidable privileges;
Application components get no exception and are checked at full strength.

||Component||Category||Detected via||Helm-managed||
{{- range .DetectedComponents }}
|{{ escapeCell .Name }}|{{ escapeCell .Category }}|{{ escapeCell (detectedVia .) }}|{{ if .HelmManaged }}Yes{{ else }}No{{ end }}|
{{- end }}
{{- end }}

h2. Summary

||Severity||Count||
{{- range .SeverityOrder }}
|{{ . }}|{{ index $.Summary . }}|
{{- end }}
|*Total*|*{{ .TotalFindings }}*|
{{- if .Suppressed }}
|*Suppressed*|*{{ len .Suppressed }}* (see Suppressed Findings below)|
{{- end }}
{{ range .Frameworks }}
h2. {{ escapeCell .Title }} Compliance (v{{ .Version }})

{expand:Full control list ({{ len .Results }} controls) — click to expand}
||Control||Title||Section||Status||Findings||Related controls||
{{- range .Results }}
|{{ .Control.ID }}|{{ escapeCell .Control.Title }}|{{ escapeCell .Control.Section }}|{{ .Status }}|{{ if eq (print .Status) "FAIL" }}{{ len .Findings }}{{ end }}|{{ crossRefs .Control }}|
{{- end }}
{expand}
{{- $notes := statusNotes . }}
{{- if $notes }}
{expand:Not Applicable / Not Implemented notes}
{{ range $notes }}{{ . }}
{{ end -}}
{expand}
{{- end }}
{{- $failing := failingControls . }}
{{- if $failing }}

{expand:Failing controls — affected resources ({{ len $failing }})}
Full detail (message, remediation) for each of these is in *Findings* below, grouped by check;
this just shows which resources make each control fail.
{{ range $failing }}
h4. {{ .Control.ID }} — {{ escapeCell .Control.Title }}
{{ range .Findings }}* *[{{ .Severity }}]* {{ .Resource.String }} — {{"{{"}}{{ .PolicyID }}{{"}}"}}
{{ end }}{{ end -}}
{expand}
{{- end }}
{{ end -}}
{{- if .ConsolidatedSummary }}
h2. Consolidated Compliance Summary

||Framework||Version||Pass||Fail||N/A||Not Implemented||Total||
{{- range .ConsolidatedSummary }}
|{{ escapeCell .Title }}|{{ .Version }}|{{ .Pass }}|{{ .Fail }}|{{ .NotApplicable }}|{{ .NotImplemented }}|{{ .Total }}|
{{- end }}
{{ end -}}
{{- if .RBACModel }}
h2. RBAC Role Model

{expand:{{ len .RBACModel }} subjects — click to expand}
||Subject||Namespace||Bindings||Permissions||Risk Flags||
{{- range .RBACModel }}
|{{ .Subject.Kind }}/{{ escapeCell .Subject.Name }}|{{ orDash .Subject.Namespace }}|{{ escapeCell (join (bindingLabels .Bindings) "\\\\") }}|{{ escapeCell (join .Permissions "\\\\") }}|{{ escapeCell (join .RiskFlags "\\\\") }}|
{{- end }}
{expand}
{{ end }}
{{- if or .FindingsByNamespace .NamespaceDetailed }}
{{ if .NamespaceDetailed }}h2. Findings by Namespace

{{ if not .FindingsByNamespace }}No findings.
{{ else }}Every finding, grouped by namespace and then by resource.
{{ range .FindingsByNamespace }}
h3. {{ if eq .Namespace "" }}Cluster-scoped{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
h4. {{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}
{{ range .Findings }}* *[{{ .Severity }}]* {{"{{"}}{{ .PolicyID }}{{"}}"}} — {{ escapeCell .Message }}{{ if .Remediation }} _Remediation: {{ escapeCell .Remediation }}_{{ end }}
{{ end }}{{ end }}{{ end }}{{ end }}
{{ else }}{expand:Findings by Namespace (index)}
One place per app/team to see what's affecting it, one line per finding — no message/remediation
text repeated here; look up the policy ID in *Findings* below for full detail on any of these.
{{ range .FindingsByNamespace }}
h3. {{ if eq .Namespace "" }}Cluster-scoped{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
*{{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}*
{{ range .Findings }}* *[{{ .Severity }}]* {{"{{"}}{{ .PolicyID }}{{"}}"}}
{{ end }}{{ end }}{{ end }}

{expand}
{{ end }}
{{ end }}
{{- if ne .ReportView "namespace" }}
h2. Findings
{{ if not .Findings }}
No findings.
{{- else -}}
{{ range .FindingsBySeverity }}
h3. {{ .Severity }} ({{ len .Findings }})

{{ severityStatus .Severity }}

||Policy ID||Title||Category||Affected||
{{- range .Checks }}
|{{ escapeCell .PolicyID }}|{{ escapeCell .Title }}|{{ escapeCell .Category }}|{{ len .Findings }}|
{{- end }}
{{ range .Checks }}
h4. {{ .PolicyID }} — {{ escapeCell .Title }}

* *Category:* {{ escapeCell .Category }}{{ if .CIS }} · *CIS:* {{ join .CIS ", " }}{{ end }}
{{- if .Remediation }}
* *Remediation:* {{ escapeCell .Remediation }}
{{- end }}
* *Affected resources ({{ len .Findings }}):*
{{ if .Collapsible }}
{expand:{{ len .Findings }} findings — click to expand}
{{ end }}
{{ range .MessageGroups }}
{{ $msg := escapeCell .Message }}{{ if eq (len .Rows) 1 }}{{ range .Rows }}{{ if .Repeat }}{{ $msg }} — *{{ .Repeat.Kind }}/{{ escapeCell .Repeat.NameTemplate }}* — repeated identically across *{{ .Repeat.Count }} {{ .Repeat.Unit }}*: {{ join .Repeat.Examples ", " }}{{ if .Repeat.Truncated }} (+{{ minus .Repeat.Count (len .Repeat.Examples) }} more){{ end }}
{{ else }}{{ $msg }} — {{ escapeCell .Finding.Resource.Kind }}/{{ escapeCell .Finding.Resource.Name }}{{ if and .Finding.Source $.MultipleSources }} ({{"{{"}}{{ .Finding.Source }}{{"}}"}}){{ end }}{{ if .Finding.Resource.Namespace }} ({{ escapeCell .Finding.Resource.Namespace }}){{ end }}
{{ end }}{{ end }}{{ else }}{{ $msg }}

||Resource||Namespace||
{{ range .Rows }}{{ if .Repeat }}|*{{ .Repeat.Kind }}/{{ escapeCell .Repeat.NameTemplate }}* — repeated identically across *{{ .Repeat.Count }} {{ .Repeat.Unit }}*: {{ join .Repeat.Examples ", " }}{{ if .Repeat.Truncated }} (+{{ minus .Repeat.Count (len .Repeat.Examples) }} more){{ end }}|—|
{{ else }}|{{ escapeCell .Finding.Resource.Kind }}/{{ escapeCell .Finding.Resource.Name }}{{ if and .Finding.Source $.MultipleSources }} ({{"{{"}}{{ .Finding.Source }}{{"}}"}}){{ end }}|{{ orDash (escapeCell .Finding.Resource.Namespace) }}|
{{ end }}{{ end }}{{ end }}
{{ end }}
{{- if .Collapsible }}

{expand}
{{ end }}
{{ end -}}
{{ end -}}
{{- end }}
{{- end }}
{{- if .Suppressed }}

{expand:Suppressed Findings ({{ len .Suppressed }})}
Matched an {{"{{"}}exclusions{{"}}"}} rule in {{"{{"}}audit.yaml{{"}}"}} — not counted in Summary and don't affect {{"{{"}}--fail-on{{"}}"}}.
{{ range .Suppressed }}
* *[{{ .Finding.Severity }}]* {{"{{"}}{{ .Finding.PolicyID }}{{"}}"}} {{ .Finding.Resource.String }} — _{{ escapeCell .Reason }}_
{{- end }}

{expand}
{{- end }}
