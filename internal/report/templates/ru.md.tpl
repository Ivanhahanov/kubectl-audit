# Отчёт аудита безопасности Kubernetes

- **Сформирован:** {{ rfc3339 .GeneratedAt }}
- **Цель:** {{ .Target }}
{{- if .ClusterVersion }}
- **Версия кластера:** {{ .ClusterVersion }}
{{- end }}
- **Загружено политик:** {{ .PoliciesLoaded }}

## Содержание

- [Область проверки](#scope)
{{- if .DetectedComponents }}
- [Обнаруженные компоненты](#detected-components)
{{- end }}
- [Сводка](#summary)
{{- range .Frameworks }}
- [Соответствие {{ .Title }}](#compliance-{{ slug .ID }})
{{- end }}
{{- if .ConsolidatedSummary }}
- [Сводное соответствие требованиям](#consolidated-summary)
{{- end }}
{{- if .RBACModel }}
- [Модель ролей RBAC](#rbac-role-model)
{{- end }}
{{- if .FindingsByNamespace }}
- [Находки по пространствам имён{{ if not .NamespaceDetailed }} (индекс){{ end }}](#findings-by-namespace)
{{- end }}
{{- if ne .ReportView "namespace" }}
- [Находки](#findings)
{{- range .FindingsBySeverity }}
  - [{{ severityRU .Severity }} ({{ len .Findings }})](#findings-{{ slug (print .Severity) }})
{{- end }}
{{- end }}
{{- if .Suppressed }}
- [Подавленные находки](#suppressed-findings)
{{- end }}

<a id="scope"></a>

## Область проверки

{{ if .Scope.OutOfScope -}}
Не охвачено этим сканированием:

{{ range .Scope.OutOfScope }}- **{{ .Title }}** — {{ .Reason }}
{{ end -}}
{{- else -}}
Полное покрытие: структурных пробелов не обнаружено — объекты control-plane, RBAC и
NetworkPolicy были доступны для наблюдения в рамках этой цели.
{{- end }}
{{- if .Scope.Caveats }}
Проверено, но с оговоркой о пониженной достоверности результата — стоит прочитать перед тем,
как доверять результату:

{{ range .Scope.Caveats }}- **{{ .Title }}** — {{ .Reason }}
{{ end -}}
{{- end }}
{{- if .DetectedComponents }}

<a id="detected-components"></a>

## Обнаруженные компоненты

Известные сторонние операторы/CNI, распознанные этим инструментом среди просканированных
ресурсов (см. `internal/thirdparty`). Системные компоненты имеют соответствующее встроенное
исключение PSS (`internal/suppress/builtin-exclusions.yaml`) для их документированных,
неизбежных привилегий; прикладные компоненты проверяются без исключений, в полном объёме.

| Компонент | Категория | Как обнаружен | Управляется Helm |
|---|---|---|---|
{{- range .DetectedComponents }}
| {{ escapeCell .Name }} | {{ .Category }} | {{ detectedVia . }} | {{ if .HelmManaged }}Да{{ else }}Нет{{ end }} |
{{- end }}
{{- end }}

<a id="summary"></a>

## Сводка

| Серьёзность | Количество |
|---|---|
{{- range .SeverityOrder }}
| {{ severityRU . }} | {{ index $.Summary . }} |
{{- end }}
| **Всего** | **{{ .TotalFindings }}** |
{{- if .Suppressed }}
| **Подавлено** | **{{ len .Suppressed }}** (см. [Подавленные находки](#suppressed-findings)) |
{{- end }}
{{ range .Frameworks }}
<a id="compliance-{{ slug .ID }}"></a>

## Соответствие {{ .Title }} (v{{ .Version }})

<details>
<summary>Полный список требований ({{ len .Results }}) — нажмите, чтобы развернуть</summary>

| Требование | Название | Раздел | Статус | Находок | Связанные требования |
|---|---|---|---|---|---|
{{- range .Results }}
| {{ .Control.ID }} | {{ escapeCell .Control.Title }} | {{ escapeCell .Control.Section }} | {{ .Status }} | {{ if eq (print .Status) "FAIL" }}{{ len .Findings }}{{ end }} | {{ crossRefs .Control }} |
{{- end }}

</details>
{{- $notes := statusNotes . }}
{{- if $notes }}
<details>
<summary>Примечания: Не применимо / Не реализовано</summary>

{{ range $notes }}{{ . }}
{{ end -}}
</details>
{{- end }}
{{- $failing := failingControls . }}
{{- if $failing }}

<details>
<summary>Невыполненные требования — затронутые ресурсы ({{ len $failing }}) — нажмите, чтобы развернуть</summary>

Полная информация (сообщение, рекомендация) по каждому из них — в разделе **Находки** ниже,
сгруппированная по проверке; здесь только показано, какие ресурсы приводят к невыполнению
требования.
{{ range $failing }}
#### {{ .Control.ID }} — {{ escapeCell .Control.Title }}
{{ range .Findings }}- **[{{ severityRU .Severity }}]** {{ .Resource.String }} — `{{ .PolicyID }}`
{{ end }}{{ end -}}

</details>
{{- end }}
{{ end -}}
{{- if .ConsolidatedSummary }}
<a id="consolidated-summary"></a>

## Сводное соответствие требованиям

| Стандарт | Версия | Выполнено | Не выполнено | Н/П | Не реализовано | Всего |
|---|---|---|---|---|---|---|
{{- range .ConsolidatedSummary }}
| {{ .Title }} | {{ .Version }} | {{ .Pass }} | {{ .Fail }} | {{ .NotApplicable }} | {{ .NotImplemented }} | {{ .Total }} |
{{- end }}
{{ end -}}
{{- if .RBACModel }}
<a id="rbac-role-model"></a>

## Модель ролей RBAC

<details>
<summary>{{ len .RBACModel }} субъектов — нажмите, чтобы развернуть</summary>

| Субъект | Пространство имён | Привязки | Права | Флаги риска |
|---|---|---|---|---|
{{- range .RBACModel }}
| {{ .Subject.Kind }}/{{ escapeCell .Subject.Name }} | {{ orDash .Subject.Namespace }} | {{ escapeCell (join (bindingLabels .Bindings) "<br>") }} | {{ escapeCell (join .Permissions "<br>") }} | {{ escapeCell (join .RiskFlags "<br>") }} |
{{- end }}

</details>
{{ end }}
{{- if or .FindingsByNamespace .NamespaceDetailed }}
<a id="findings-by-namespace"></a>

{{ if .NamespaceDetailed }}## Находки по пространствам имён

{{ if not .FindingsByNamespace }}Находок нет.
{{ else }}Каждая находка, сгруппированная по пространству имён, затем по ресурсу.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Кластерный уровень{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
#### {{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}
{{ range .Findings }}- **[{{ severityRU .Severity }}] `{{ .PolicyID }}`** — {{ .Message }}{{ if .Remediation }} _Рекомендация: {{ .Remediation }}_{{ end }}
{{ end }}{{ end }}{{ end }}{{ end }}
{{ else }}<details>
<summary><h2 style="display:inline">Находки по пространствам имён (индекс)</h2></summary>

Одно место на приложение/команду, чтобы увидеть, что на него влияет, одна строка на находку —
текст сообщения/рекомендации здесь не повторяется; ищите ID проверки в разделе **Находки** ниже
для полной информации по любой из них.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Кластерный уровень{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
**{{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}**
{{ range .Findings }}- **[{{ severityRU .Severity }}]** `{{ .PolicyID }}`
{{ end }}{{ end }}{{ end }}

</details>
{{ end }}
{{ end }}
{{- if ne .ReportView "namespace" }}
<a id="findings"></a>

## Находки
{{ if not .Findings }}
Находок нет.
{{- else -}}
{{ range .FindingsBySeverity }}
<a id="findings-{{ slug (print .Severity) }}"></a>

### {{ severityRU .Severity }} ({{ len .Findings }})

| ID проверки | Название | Категория | Затронуто |
|---|---|---|---|
{{- range .Checks }}
| [{{ escapeCell .PolicyID }}](#check-{{ slug .PolicyID }}) | {{ escapeCell .Title }} | {{ escapeCell .Category }} | {{ len .Findings }} |
{{- end }}
{{ range .Checks }}
<a id="check-{{ slug .PolicyID }}"></a>

#### [{{ .PolicyID }}] {{ .Title }}

- **Категория:** {{ .Category }}{{ if .CIS }} · **CIS:** {{ join .CIS ", " }}{{ end }}
{{- if .Remediation }}
- **Рекомендация:** {{ .Remediation }}
{{- end }}
- **Затронутые ресурсы ({{ len .Findings }}):**
{{ if .Collapsible }}
<details>
<summary>{{ len .Findings }} находок — нажмите, чтобы развернуть</summary>
{{ end }}
{{ range .MessageGroups }}
{{ $msg := .Message }}{{ if eq (len .Rows) 1 }}{{ range .Rows }}{{ if .Repeat }}  {{ $msg }} — **{{ .Repeat.Kind }}/{{ escapeCell .Repeat.NameTemplate }}** — повторяется идентично в **{{ .Repeat.Count }} {{ unitRU .Repeat.Unit }}**: {{ join .Repeat.Examples ", " }}{{ if .Repeat.Truncated }} (+ ещё {{ minus .Repeat.Count (len .Repeat.Examples) }}){{ end }}
{{ else }}  {{ $msg }} — {{ escapeCell .Finding.Resource.Kind }}/{{ escapeCell .Finding.Resource.Name }}{{ if and .Finding.Source $.MultipleSources }} (`{{ .Finding.Source }}`){{ end }}{{ if .Finding.Resource.Namespace }} ({{ escapeCell .Finding.Resource.Namespace }}){{ end }}
{{ end }}{{ end }}{{ else }}  {{ .Message }}

  | Ресурс | Пространство имён |
  |---|---|
{{ range .Rows }}{{ if .Repeat }}  | **{{ .Repeat.Kind }}/{{ escapeCell .Repeat.NameTemplate }}** — повторяется идентично в **{{ .Repeat.Count }} {{ unitRU .Repeat.Unit }}**: {{ join .Repeat.Examples ", " }}{{ if .Repeat.Truncated }} (+ ещё {{ minus .Repeat.Count (len .Repeat.Examples) }}){{ end }} | — |
{{ else }}  | {{ escapeCell .Finding.Resource.Kind }}/{{ escapeCell .Finding.Resource.Name }}{{ if and .Finding.Source $.MultipleSources }} (`{{ .Finding.Source }}`){{ end }} | {{ orDash (escapeCell .Finding.Resource.Namespace) }} |
{{ end }}{{ end }}{{ end }}
{{ end }}
{{- if .Collapsible }}

</details>
{{ end }}
{{ end -}}
{{ end -}}
{{- end }}
{{- end }}
{{- if .Suppressed }}

<a id="suppressed-findings"></a>

<details>
<summary><h2 style="display:inline">Подавленные находки ({{ len .Suppressed }})</h2></summary>

Совпало с правилом `exclusions` в `audit.yaml` — не учитывается в Сводке и не влияет на
`--fail-on`.
{{ range .Suppressed }}
- **[{{ severityRU .Finding.Severity }}] `{{ .Finding.PolicyID }}`** {{ .Finding.Resource.String }} — _{{ .Reason }}_
{{- end }}

</details>
{{- end }}
