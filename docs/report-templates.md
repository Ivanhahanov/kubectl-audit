# Настройка `report.md`

`report.md` рендерится из Go [`text/template`](https://pkg.go.dev/text/template), а не из
захардкоженной сборки строк в Go. Встроенный шаблон находится в
[`internal/report/templates/default.md.tpl`](../internal/report/templates/default.md.tpl)
и встроен в бинарник; `--report-template <file>` (или `output.template` в
`audit.yaml`) полностью заменяет его своим собственным.

## Начало работы

```sh
# Записать встроенный шаблон на диск как отправную точку
kubectl audit template dump --out report.md.tpl

# Отредактировать его, затем использовать
kubectl audit scan --report-template report.md.tpl
```

Поскольку пользовательский шаблон полностью заменяет шаблон по умолчанию, вы можете свободно
перестраивать всё что угодно — убирать неинтересные вам разделы, менять их порядок, добавлять
собственные заголовки/брендинг или формировать совершенно другой формат вывода (лишь бы это был
валидный синтаксис шаблонов Go; результат необязательно должен быть Markdown).

## Данные, доступные шаблону

Шаблон выполняется над значением `report.TemplateData`:

| Поле | Тип | Примечания |
|---|---|---|
| `.GeneratedAt` | `time.Time` | Используйте `{{ rfc3339 .GeneratedAt }}` или вызывайте `.Format` напрямую. |
| `.Target` | `string` | Например, `cluster:my-context` или `static:./manifests`. |
| `.ClusterVersion` | `string` | Например, `v1.29.4`. Пусто для сканирования только статических манифестов. |
| `.ClusterEndpoint` | `string` | URL API-сервера из kubeconfig (`rest.Config.Host`) — несмотря на название, не всегда буквальный IP-адрес. Пусто для сканирования только статических манифестов. |
| `.Owner` | `string` | Произвольный текст «кто отвечает за этот отчёт» — `output.owner`/`--owner`. Пусто, если не задано. |
| `.PoliciesLoaded` | `int` | |
| `.SeverityOrder` | `[]findings.Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, именно в таком порядке. |
| `.Summary` | `map[Severity]int` | Индексируется через `{{ index .Summary . }}` внутри `range .SeverityOrder`. |
| `.TotalFindings` | `int` | |
| `.Findings` | `[]findings.Finding` | Все находки, отсортированные от самой серьёзной. |
| `.FindingsBySeverity` | `[]report.SeverityGroup` | Предварительно сгруппированы: `{Severity, Findings}` для каждой непустой корзины серьёзности. |
| `.Frameworks` | `[]compliance.Scorecard` | По одной записи на каждое значение `--frameworks`, с полями `.ID`, `.Title`, `.Version`, `.Results`. |
| `.ConsolidatedSummary` | `[]compliance.FrameworkSummary` | Счётчики pass/fail/N-A/not-implemented по каждому фреймворку. |
| `.RBACModel` | `[]rbac.SubjectModel` | Эффективные права и флаги риска по каждому субъекту. |

`compliance.ControlResult` (внутри `.Frameworks[].Results`) имеет поля `.Control` (`ID`, `Title`,
`Section`, `Applicable`, `NAReason`, `Note`, `CrossRefs`), `.Status`, `.FindingIDs`, `.Resources`
и `.Findings` (заполняется только когда `.Status` равен `FAIL`).

Раздел «Findings» шаблона по умолчанию на самом деле рендерится через `.FindingsBySeverity[].Checks`
(`[]report.CheckGroup`, по одной на каждый policy ID внутри уровня серьёзности), а не напрямую через
`.Findings`/`.FindingsBySeverity` — группировка по проверке выносит заголовок/рекомендацию/ссылки на
CIS каждой политики наружу, чтобы они рендерились один раз, а не один раз на каждый затронутый ресурс.
`.Title`/`.Category`/`.Remediation` у `CheckGroup` уже учитывают переопределение из `knowledgeBaseFile`
(см. [База знаний](./triage.md)) — одна база знаний, одно и то же содержимое в triage, Jira и отчёте.

Category/Standard/Remediation у `CheckGroup` рендерятся как компактная таблица ключ-значение (а не
список — так лучше читается в корпоративном отчёте при беглом просмотре), за которой следуют его
затронутые ресурсы.

Каждый `CheckGroup` далее группирует свои находки по сообщению (`.MessageGroups`, `[]report.MessageGroup`:
`.Message`, `.Rows`) — находки, чьё сообщение совпадает после удаления из него собственного имени
ресурса/неймспейса, или которые разделяют предоставленный анализатором `DedupKey` (см.
`findings.Finding.DedupKey`), попадают в один и тот же бакет и получают одну строку сообщения вместо
повторения её на каждый ресурс. Внутри бакета находки, разделяющие Kind и «форму имени» — либо
идентичное буквальное имя, либо (с `output.groupByNamePattern`, включено по умолчанию) имена, которые
отличаются только сегментом сгенерированного идентификатора (UUID или другой длинный hex/цифровой
прогон) — появляющиеся не менее `output.namespaceGroupThreshold` раз (по умолчанию `3`; см.
[Снижение шума](./getting-started.md)), схлопываются в одну `report.AffectedRow` на `.Rows` — либо
`.Finding` (обычная `findings.Finding`), либо `.Repeat` (`report.RepeatGroup`: `.Kind`, `.NameTemplate`,
`.Unit`, `.Count`, `.Examples`, ограниченные 8 штуками, `.Truncated`). `CheckGroup.Collapsible` равен
true, как только у проверки становится больше 8 находок в сумме — шаблон по умолчанию оборачивает
затронутые ресурсы такой проверки в `<details>` (или `{expand}` в шаблоне Confluence ниже), чтобы
проверка, срабатывающая на множестве ресурсов, не выталкивала всё остальное за пределы экрана, не
теряя при этом ни одной строки. См.
[`CheckGroup`/`MessageGroup`/`AffectedRow`/`RepeatGroup` в `internal/report/template.go`](../internal/report/template.go)
для полного списка полей, если вы настраиваете эту часть шаблона.

## Функции шаблона

| Функция | Сигнатура | Назначение |
|---|---|---|
| `escapeCell` | `(v any) string` | Экранирует `\|` и переводы строк для ячейки таблицы (Markdown или Confluence — обе используют `\|` как символ экранирования). Принимает `any`, а не `string` — вызывается в том числе на именованных строковых типах (например, `thirdparty.Category`), которые параметр, типизированный как `string`, отклонил бы во время выполнения шаблона. |
| `orDash` | `(s string) string` | Возвращает `"-"` для пустой строки, иначе `s`. |
| `join` | `(elems []string, sep string) string` | `strings.Join`, порядок аргументов соответствует синтаксису вызова в шаблоне. |
| `minus` | `(a, b int) int` | `a - b` — используется для счётчиков усечения вида «(+N ещё)». |
| `rfc3339` | `(t time.Time) string` | Временная метка в формате RFC3339. |
| `slug` | `(s string) string` | Идентификатор в нижнем регистре, безопасный для якорей, например для `<a id="...">`. Только для шаблона Markdown — макрос `{toc}` в Confluence строит собственную навигацию, см. ниже. |
| `bindingLabels` | `(bindings []rbac.BindingRef) []string` | Дедуплицированные метки вида `"Kind/Name"` для строки модели ролей RBAC. |
| `crossRefs` | `(c compliance.Control) string` | Форматирует `c.CrossRefs`, например как `"CIS: 5.2.4, 5.7.3"`. |
| `anyCrossRefs` | `(results []compliance.ControlResult) bool` | Сообщает, есть ли хотя бы у одного контроля непустой `CrossRefs` — используется, чтобы полностью скрыть столбец «Related controls», когда он всегда был бы пуст (например, в собственной таблице CIS: `crossRefs` указывают *на* CIS из других фреймворков, а не *из* него). |
| `detectedVia` | `(d thirdparty.Detection) string` | Форматирует, почему компонент был обнаружен (совпадение по группе CRD / метке, со счётчиками). |
| `failingControls` | `(sc compliance.Scorecard) []compliance.ControlResult` | Фильтрует результаты scorecard только по `FAIL`. |
| `statusNotes` | `(sc compliance.Scorecard) []string` | Предварительно отформатированные строки-пункты `NAReason`/`Note` для строк scorecard со статусом `NOT_APPLICABLE`/`NOT_IMPLEMENTED`. |
| `severityRU` | `(s findings.Severity) string` | Переводит константу `Severity` на русский (`CRITICAL` → «Критическая» и т. д.) — используется `ru.md.tpl` для локализации. |
| `unitRU` | `(unit string) string` | Переводит единицу `RepeatGroup.Unit` (`"namespaces"`/`"objects"`) на русский — используется `ru.md.tpl`. |

## Пример: минимальный пользовательский шаблон

```gotemplate
# Audit of {{ .Target }}

{{ .TotalFindings }} finding(s) as of {{ rfc3339 .GeneratedAt }}.

{{ range .FindingsBySeverity }}
## {{ .Severity }}
{{ range .Findings }}- {{ .Resource.String }}: {{ .Message }}
{{ end }}{{ end }}
```

Сохраните его и выполните `kubectl audit scan --report-template minimal.md.tpl` — `report.md` будет
содержать только это, ничего больше из шаблона по умолчанию.

## Русскоязычный шаблон отчёта

`--report-lang ru` (или `output.reportLang: ru` в конфиге) переключает встроенный шаблон Markdown на
`internal/report/templates/ru.md.tpl` — та же структура и те же якоря, что и у `default.md.tpl`, но
собственные заголовки/подписи отчёта («Категория», «Рекомендация», «Затронутые ресурсы», ...) на
русском языке вместо английского. Это один статически переведённый шаблон, а не общая система
интернационализации — он меняет только окружающий каркас.

Собственные Title/Message/Remediation находки остаются на том языке, на котором их сформировала
породившая их политика/анализатор, если только база знаний не переопределяет их (см.
[База знаний](./triage.md)) — поставляемая по умолчанию база знаний уже написана на русском, поэтому
`--report-lang ru` без какой-либо дополнительной настройки уже даёт полностью русские заголовки проверок/
рекомендации, а не только каркас. Игнорируется, если задан `--report-template` — тот же прецедент, что и
везде, где пользовательский шаблон полностью заменяет встроенный.

```sh
kubectl audit scan --report-lang ru
# или выгрузить его как отправную точку для настройки:
kubectl audit template dump --format ru --out report.ru.md.tpl
```

## Вывод в Confluence

`--output confluence=<file>` (или `output.confluence` в `audit.yaml`) записывает тот же отчёт в виде
**вики-разметки Confluence Server/Data Center** — заголовки `h2.`, таблицы `||table||`, сворачиваемые
блоки `{expand}`, ссылки `[text|url]` — готовой к вставке прямо на страницу Confluence. Это нацелено
именно на вики-разметку Server/Data Center; Confluence **Cloud** использует другой формат
(Storage Format/ADF) и не поддерживается.

Встроенный шаблон находится в
[`internal/report/templates/confluence.tpl`](../internal/report/templates/confluence.tpl),
встроен тем же способом, что и `default.md.tpl`, и выполняется над тем же самым `report.TemplateData`
— различаются только текст шаблона и набор функций. `--confluence-template <file>` (или
`output.confluenceTemplate`) полностью заменяет его, точно так же, как `--report-template` делает это
для Markdown.

```sh
kubectl audit template dump --format confluence --out confluence.tpl
kubectl audit scan --confluence-template confluence.tpl --output confluence=report.confluence
```

Набор функций для Confluence такой же, как у Markdown выше, минус `slug` (не нужна — вставьте макрос
`{toc:maxLevel=3}` ближе к началу, и Confluence построит собственную навигацию по заголовкам страницы) и
плюс одно дополнение, специфичное для Confluence:

| Функция | Сигнатура | Назначение |
|---|---|---|
| `severityStatus` | `(s findings.Severity) string` | Макрос `{status:colour=...\|title=...}` — цветовой значок рядом с заголовком каждого уровня серьёзности. У Markdown эквивалента нет. |

Одна оговорка: текст `Message`/`Remediation`, который политика или запись базы знаний написали в
расчёте на рендерер Markdown (вручную написанный `` `code` `` или `[text](url)`), в выводе Confluence
рендерится как буквальный текст, без преобразования — так же, как при вставке текста, написанного в
Markdown, в описание Jira Server/DC (см. [Triage > Markdown и вики-разметка](./triage.md)). Пишите
свободный текст проверок/базы знаний в вики-разметке, если для вас важен вывод в Confluence, либо
оставляйте его простым (без встроенного форматирования), чтобы он нормально читался в обоих случаях.
