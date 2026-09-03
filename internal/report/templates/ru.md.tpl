# Отчёт аудита безопасности Kubernetes

|  |  |
|---|---|
| Сформирован | {{ rfc3339 .GeneratedAt }} |
| Цель | {{ escapeCell .Target }} |
{{- if .ClusterVersion }}
| Версия кластера | {{ .ClusterVersion }} |
{{- end }}
{{- if .ClusterEndpoint }}
| API-сервер кластера | {{ escapeCell .ClusterEndpoint }} |
{{- end }}
{{- if .Owner }}
| Ответственный | {{ escapeCell .Owner }} |
{{- end }}
| Загружено политик | {{ .PoliciesLoaded }} |

## Содержание

- [Контекст](#context)
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
- [Сработки по пространствам имён{{ if not .NamespaceDetailed }} (индекс){{ end }}](#findings-by-namespace)
{{- end }}
{{- if ne .ReportView "namespace" }}
- [Сработки](#findings)
{{- range .FindingsBySeverity }}
  - [{{ severityRU .Severity }} ({{ len .Findings }})](#findings-{{ slug (print .Severity) }})
{{- end }}
{{- end }}
{{- if .Suppressed }}
- [Подавленные сработки](#suppressed-findings)
{{- end }}

<a id="context"></a>

## Контекст

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

### Обнаруженные компоненты

Известные сторонние операторы/CNI, распознанные среди просканированных ресурсов. Системные
компоненты имеют документированное исключение для необходимых им повышенных привилегий;
прикладные компоненты проверяются без исключений, в полном объёме.

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
| **Подавлено** | **{{ len .Suppressed }}** (см. [Подавленные сработки](#suppressed-findings)) |
{{- end }}
{{ range .Frameworks }}
<a id="compliance-{{ slug .ID }}"></a>

## Соответствие {{ .Title }} (v{{ .Version }})

<details>
<summary>Полный список требований ({{ len .Results }}) — нажмите, чтобы развернуть</summary>

| Требование | Название | Раздел | Статус | Сработок | Связанные требования |
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

Полная информация (сообщение, рекомендация) по каждому из них — в разделе **Сработки** ниже,
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

{{ if .NamespaceDetailed }}## Сработки по пространствам имён

{{ if not .FindingsByNamespace }}Сработок нет.
{{ else }}Каждая сработка, сгруппированная по пространству имён, затем по ресурсу.
{{ range .FindingsByNamespace }}
### {{ if eq .Namespace "" }}Кластерный уровень{{ else }}{{ .Namespace }}{{ end }}
{{ range .Resources }}
#### {{ .Resource.Kind }}/{{ escapeCell .Resource.Name }}
{{ range .Findings }}- **[{{ severityRU .Severity }}] `{{ .PolicyID }}`** — {{ .Message }}{{ if .Remediation }} _Рекомендация: {{ .Remediation }}_{{ end }}
{{ end }}{{ end }}{{ end }}{{ end }}
{{ else }}<details>
<summary><h2 style="display:inline">Сработки по пространствам имён (индекс)</h2></summary>

Одно место на приложение/команду, чтобы увидеть, что на него влияет, одна строка на сработку —
текст сообщения/рекомендации здесь не повторяется; ищите ID проверки в разделе **Сработки** ниже
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

## Сработки
{{ if not .Findings }}
Сработок нет.
{{- else -}}
{{ range .FindingsBySeverity }}
<a id="findings-{{ slug (print .Severity) }}"></a>

### {{ severityRU .Severity }} ({{ len .Findings }})
{{ range .Checks }}
<a id="check-{{ slug .PolicyID }}"></a>

#### [{{ .PolicyID }}] {{ .Title }}

|  |  |
|---|---|
| Категория | {{ escapeCell .Category }} |
{{- if .CIS }}
| CIS | {{ join .CIS ", " }} |
{{- end }}
{{- if .Remediation }}
| Рекомендация | {{ escapeCell .Remediation }} |
{{- end }}

{{ if .Collapsible }}
<details>
<summary>{{ len .Findings }} сработок — нажмите, чтобы развернуть</summary>
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
<summary><h2 style="display:inline">Подавленные сработки ({{ len .Suppressed }})</h2></summary>

Совпало с правилом `exclusions` в `audit.yaml` — не учитывается в Сводке и не влияет на
`--fail-on`.
{{ range .Suppressed }}
- **[{{ severityRU .Finding.Severity }}] `{{ .Finding.PolicyID }}`** {{ .Finding.Resource.String }} — _{{ .Reason }}_
{{- end }}

</details>
{{- end }}
