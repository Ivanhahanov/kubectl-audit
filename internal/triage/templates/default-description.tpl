{{.Finding.Message}}
{{if .Finding.Remediation}}
*Remediation:*
{{.Finding.Remediation}}
{{end -}}
{{if .Finding.VerificationSteps}}
*Verification steps (confirm before treating as urgent):*
{{.Finding.VerificationSteps}}
{{end -}}
{{if .Finding.CIS}}
*CIS:* {{join .Finding.CIS ", "}}
{{end -}}
{{if .Entry.Note}}
*Triage note:* {{.Entry.Note}}
{{end -}}
----
kubectl-audit finding: {{.Finding.ID}} (policy {{.Finding.PolicyID}}, source {{.Finding.Source}})
