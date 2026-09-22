{{.Content.Description}}

{{if .Content.Technical -}}
*Technical detail:*
{{.Content.Technical}}

{{end -}}
{{if .Content.Remediation -}}
*Remediation:*
{{.Content.Remediation}}

{{end -}}
{{if .Content.VerificationSteps -}}
*Verification steps (confirm before treating as urgent):*
{{.Content.VerificationSteps}}

{{end -}}
{{if .PrimaryStandard -}}
*Standard:* {{.PrimaryStandard}}

{{end -}}
{{if .RelatedStandards -}}
*Related standards:* {{.RelatedStandards}}

{{end -}}
{{if .Entry.Note -}}
*Triage note:* {{.Entry.Note}}

{{end -}}
----
kubectl-audit finding: {{.Finding.ID}} (policy {{.Finding.PolicyID}}, source {{.Finding.Source}})
