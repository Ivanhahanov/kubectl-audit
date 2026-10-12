# kubectl-audit-server: мультикластерная агрегация, триаж и автоматизация

Всё на этой странице опционально. `kubectl audit scan` и `kubectl triage` работают в точности так,
как описано в [Начале работы](./getting-started.md) и [Триаже](./triage.md), без какого-либо
участия сервера — findings.json и локальный triage-state.yaml по-прежнему остаются вариантом по
умолчанию, навсегда. `kubectl-audit-server` — это отдельный опциональный бинарник для случаев,
когда вы аудируете более одного кластера и хотите централизовать находки, решения триажа, записи
базы знаний и правила исключений вместо того, чтобы дублировать их по кластерам — а также
несколько вещей, которые один локальный вызов CLI в принципе не может делать: корреляцию между
источниками, правила автоматизации и запуск сканирований по требованию.

Эта страница — пошаговый разбор каждой возможности сервера, в том порядке, в котором вы бы к ним
реально обращались. Каждый раздел можно копировать и выполнять как есть.

## Содержание

- [Быстрый старт (без Kubernetes)](#быстрый-старт-без-kubernetes)
- [Документация API (Swagger/OpenAPI)](#документация-api-swaggeropenapi)
- [Регистрация кластера и отправка результатов сканирования](#регистрация-кластера-и-отправка-результатов-сканирования)
- [Триаж через сервер](#триаж-через-сервер)
- [Приём находок от других инструментов (OpenReports)](#приём-находок-от-других-инструментов-openreports)
- [Централизованная база знаний](#централизованная-база-знаний)
- [Централизованные правила исключений](#централизованные-правила-исключений)
- [Правила автоматизации](#правила-автоматизации)
- [`inspect`: узкоспециализированный CLI для диагностики в режиме только чтения](#inspect-узкоспециализированный-cli-для-диагностики-в-режиме-только-чтения)
- [MCP-адаптер (интеграция с AI-агентами)](#mcp-адаптер-интеграция-с-ai-агентами)
- [Развёртывание в реальном кластере (Helm-чарт)](#развёртывание-в-реальном-кластере-helm-чарт)

## Быстрый старт (без Kubernetes)

Сервер — это просто Go-бинарник плюс Postgres: для самого *запуска* кластер не нужен (только для
*аудита*). Быстрее всего опробовать все не привязанные к Kubernetes возможности ниже (приём
находок, триаж, базу знаний, правила исключений, сопоставление правил автоматизации) через
`docker-compose.yml` в корне репозитория:

```sh
docker build --target server -t kubectl-audit-server:demo .
docker compose up
```

Это запускает Postgres и сервер (`ADMIN_TOKEN=demo-admin-token`, слушает `:8080`, миграции
применяются автоматически при старте). Далее везде предполагается, что сервер доступен по адресу
`http://localhost:8080` — скорректируйте, если развернули его иначе.

## Документация API (Swagger/OpenAPI)

Каждый эндпоинт ниже аннотирован комментариями [swaggo](https://github.com/swaggo/swag) и
обслуживается как интерактивный Swagger UI, без какого-либо отдельного инструмента:

```
http://localhost:8080/swagger/index.html
```

Исходная спецификация OpenAPI 2.0, на которой строится этот UI, находится по адресу
`http://localhost:8080/swagger/doc.json` (также закоммичена как
`cmd/kubectl-audit-server/docs/swagger.json`/`.yaml` — удобно для импорта в Postman/Insomnia или
генерации клиента). Нажмите «Authorize» в UI и вставьте `Bearer <admin-token>` или
`Bearer <cluster-token>`, чтобы отправлять запросы прямо из браузера — действует то же разделение
на admin- и cluster-токены, что описано ниже.

Если вы меняете форму запроса/ответа у обработчика или добавляете новый эндпоинт, перегенерируйте
спецификацию:

```sh
go run github.com/swaggo/swag/cmd/swag@latest init \
  -g cmd/kubectl-audit-server/main.go -o cmd/kubectl-audit-server/docs --parseInternal --pd
```

## Регистрация кластера и отправка результатов сканирования

Каждый кластер (точнее, каждая отдельная сущность, отправляющая результаты сканирования) получает
собственный bearer-токен, выпускаемый один раз admin-вызовом и впоследствии никогда не хранимый на
сервере в открытом виде:

```sh
curl -X POST http://localhost:8080/api/v1/clusters \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"name":"prod-eu-west-1","owner":"platform-team"}'
# -> {"id":"...", "name":"prod-eu-west-1", "token":"..."}  — сохраните токен, он показывается один раз
```

Отправьте реальное сканирование новой командой CLI:

```sh
kubectl audit scan -A --output json=findings.json
kubectl-audit push --server http://localhost:8080 --token <cluster token> --findings findings.json
# либо: задайте KUBECTL_AUDIT_SERVER_URL / KUBECTL_AUDIT_SERVER_TOKEN и опустите флаги
```

Находки дедуплицируются по `(cluster, source, fingerprint)` — повторная отправка того же
сканирования никогда не создаёт дубликатов, только обновляет `last_seen`; находка, переставшая
появляться, автоматически получает запись триажа (если она есть) со статусом `resolved`. Точные
правила формирования fingerprint см. в заметках об архитектуре в истории коммитов репозитория,
если интересно.

## Триаж через сервер

`kubectl triage` (тот же интерактивный TUI, `export` и `jira-sync`, что вы уже знаете) может
сохранять решения централизованно вместо локального `triage-state.yaml`, **без каких-либо других
изменений в поведении** — достаточно добавить четыре вещи:

```sh
kubectl triage \
  --triage-server http://localhost:8080 \
  --triage-server-cluster-id <cluster id> \
  --triage-server-token <admin token> \
  --findings findings.json
```

Чтение/запись триажа — это **действие уровня admin («эксперта»)**, намеренно отделённое от
собственного push-токена кластера: этот токен предназначен только для приёма данных
(`POST /api/v1/ingest/*`) и не даёт доступа к `/api/v1/triage/*` — утёкший push-токен может
подсунуть поддельные находки, но не может прочитать чужие заметки триажа или ссылки на Jira.
Поэтому `--triage-server-token` здесь — это admin-токен сервера, а не токен кластера, полученный
при регистрации, а `--triage-server-cluster-id` явно указывает, находки какого кластера вы
проверяете (поле `id` из ответа при регистрации этого кластера, а не его токен).

(`--triage-server-source` по умолчанию равен `kubectl-audit`; задавайте его явно, если проверяете
источник, полученный через OpenReports — см. ниже.) Токен также можно взять из
`$KUBECTL_AUDIT_TRIAGE_SERVER_TOKEN`, а у `--triage-server`/`--triage-server-source`/
`--triage-server-cluster-id` есть эквиваленты в `audit.yaml`
(`triage.server.baseUrl`/`triage.server.source`/`triage.server.clusterId`), так что не нужно
повторять флаги на каждом запуске — `clusterId` не является учётными данными (сам по себе он
ничего не даёт), поэтому его можно спокойно коммитить рядом с `baseUrl`/`source`.

Всё остальное — отметка confirmed/false-positive/won't-fix, заметки, массовые действия и даже
`'j'` для создания тикета в Jira — работает точно так же; меняется только то, *куда* сохраняется
решение.

**`--triage-server` всегда означает, что находки тоже приходят с сервера**, а не только то, что
туда сохраняются решения — `--findings`/`triage.output.json` в этом режиме полностью игнорируются,
локальное сканирование не требуется. Именно это делает возможным просмотр находок, отправленных
кластером, который вы лично никогда не сканировали (мультикластерный сценарий — хаб, агрегирующий
сканирования из разных источников). Это намеренно один режим или другой: более ранняя версия делала
этот выбор неявно (находки с сервера брались только если на диске случайно не оказывалось локального
findings.json), что было неожиданным поведением — то, увидите ли вы серверные или устаревшие
локальные данные, зависело от случайно оставшегося файла, и ни от чего больше.

Можно подтвердить, что решение действительно сохранилось, и обычным вызовом curl:

```sh
curl -X PATCH "http://localhost:8080/api/v1/triage/kubectl-audit/<finding id>?cluster_id=<cluster id>" \
  -H "Authorization: Bearer <admin token>" -H "Content-Type: application/json" \
  -d '{"status":"confirmed","note":"real escalation path, needs remediation"}'

curl "http://localhost:8080/api/v1/triage?cluster_id=<cluster id>&source=kubectl-audit&status=confirmed" \
  -H "Authorization: Bearer <admin token>"
```

## Приём находок от других инструментов (OpenReports)

Сервер также принимает документы [openreports.io](https://openreports.io) `Report`/`ClusterReport`
(формат, который уже используют Policy Reporter от Kyverno, Trivy-operator и другие) — полезно,
если вы хотите единый процесс триажа для kubectl-audit и всего остального, что уже сканирует ваши
кластеры:

```sh
curl -X POST http://localhost:8080/api/v1/ingest/openreports \
  -H "Authorization: Bearer <cluster token>" -H "Content-Type: application/json" \
  --data-binary @my-kyverno-policyreport.json
```

Находками становятся только результаты `fail`/`warn` (`pass`/`skip` не являются проблемами;
`error` означает, что *сам движок политик* не смог выполнить оценку, а не то, что найдена проблема
в кластере). Поле `source` каждого результата становится собственным источником вида
`openreports:<tool>` — например, `openreports:kyverno` — полностью отдельным от находок
`kubectl-audit`; между источниками ничего никогда не объединяется. Один документ может даже
смешивать результаты от разных инструментов (спецификация допускает переопределение `source` для
каждого результата отдельно) — сервер корректно разбивает это на отдельные сканирования по
источникам, а не помечает всё одним общим ярлыком.

У находок, полученных из OpenReports, нет Remediation/CIS/VerificationSteps (у этого источника
просто нет соответствующих данных) — триаж по-прежнему работает так же; шаблон Jira просто
отображает эти разделы пустыми. Проверяйте их из CLI с `--triage-server-source
openreports:kyverno`, либо напрямую через API так же, как выше, просто с другим `source` в
URL/строке запроса.

## Централизованная база знаний

У сегодняшнего локального `knowledgeBaseFile` (переопределения title/description/remediation по
каждой проверке) есть серверный аналог, с ключом по ID политики, защищённый **admin**-токеном (это
общеорганизационная конфигурация, а не данные одного кластера):

```sh
curl -X PUT http://localhost:8080/api/v1/knowledge-base/workload.no-latest-tag \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{
    "title": "Uses the :latest tag",
    "description": "Pinning to :latest makes deployments non-reproducible and silently mutable.",
    "remediation": "Pin to a specific digest or immutable version tag.",
    "labels": ["supply-chain"]
  }'

curl http://localhost:8080/api/v1/knowledge-base/workload.no-latest-tag \
  -H "Authorization: Bearer demo-admin-token"
```

(Пока нет CLI-обвязки, которая бы *потребляла* это с сервера — эндпоинты существуют, чтобы будущий
клиент или ваша собственная система могли централизовать это вместо ручной синхронизации YAML-файла
между кластерами.)

## Централизованные правила исключений

Та же идея для `exclusionRules` из `audit.yaml` — если `ClusterID` не задан, правило применяется ко
всем зарегистрированным кластерам; задайте его, чтобы ограничить правило (например, известный
ложноположительный результат, специфичный для конфигурации одного кластера) только этим кластером:

```sh
# Глобальное — применяется везде
curl -X POST http://localhost:8080/api/v1/exclusion-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"policyIds":["workload.no-latest-tag"],"match":{"kind":"Deployment","namespace":"kube-system"},"reason":"known false positive on system components"}'

# Ограничено одним кластером
curl -X POST http://localhost:8080/api/v1/exclusion-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"clusterId":"<cluster id>","reason":"legacy workloads pending decommission","match":{"name":"legacy-*"}}'

# Список всего, что применяется к одному кластеру (глобальные + собственные правила этого кластера)
curl "http://localhost:8080/api/v1/exclusion-rules?cluster_id=<cluster id>" \
  -H "Authorization: Bearer demo-admin-token"

curl -X DELETE http://localhost:8080/api/v1/exclusion-rules/<rule id> \
  -H "Authorization: Bearer demo-admin-token"
```

## Правила автоматизации

Правило автоматизации сопоставляет находки по серьёзности/статусу/источнику/«нет ссылки на Jira
уже N часов» и фиксирует, какое действие *сработало бы* — создание тикета в Jira, либо (зарезервировано
для будущей интеграции с AI-агентом) действие `agent_triage`. **Выполнение действия пока не
подключено** — для этого на данном этапе намеренно не стали строить новую инфраструктуру учётных
данных/агентов (см. собственное поле `detail` правила, которое прямо об этом сообщает) — но сам
движок сопоставления реальный: создайте правило, подтвердите подходящую находку, и она будет
каждый раз корректно опознана.

```sh
curl -X POST http://localhost:8080/api/v1/automation-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{
    "name": "critical confirmed needs a ticket",
    "enabled": true,
    "trigger": {"minSeverity": "CRITICAL", "status": "confirmed", "noJiraLinkForHours": 24},
    "action": {"type": "file_jira"}
  }'

# Запустить один проход оценки немедленно (kubectl-audit-worker также
# делает это автоматически каждые AUTOMATION_INTERVAL_SECONDS, по умолчанию 300с)
curl -X POST http://localhost:8080/api/v1/automation-rules/evaluate \
  -H "Authorization: Bearer demo-admin-token"
```

Подтверждённая находка CRITICAL старше 24 часов без ссылки на Jira появится в ответе с
`"attempted": false` и полем `detail`, объясняющим почему — это ожидаемое, честное состояние на
сегодняшний день.

## `inspect`: узкоспециализированный CLI для диагностики в режиме только чтения

Отдельно от сервера, но созданный по той же причине, по которой правила автоматизации упоминают
действие `agent_triage`: способ ответить на один конкретный вопрос о живом кластере без полного
сканирования — и, намеренно, без передачи реальных учётных данных кластера чему-либо, у чего их ещё
нет (см. раздел про MCP ниже).

```sh
kubectl-audit inspect resource Deployment/web -n default
kubectl-audit inspect rbac-chain --subject ServiceAccount/deploy-bot -n ci
kubectl-audit inspect rbac-chain --subject Group/system:masters
```

`inspect resource` никогда не может получить `Secret`, ни при каком флаге — это жёсткое,
безусловное правило (строже, чем флаг сканирования `--read-secret-values`), поскольку вывод
inspect может попасть в контекст LLM или в логи.

## MCP-адаптер (интеграция с AI-агентами)

`cmd/kubectl-audit-mcp` — это сервер [Model Context Protocol](https://modelcontextprotocol.io),
предоставляющий `inspect_resource` и `inspect_rbac_chain` как инструменты, которые может вызывать
AI-агент — реализован как тонкая обёртка, которая выполняет (`exec`) описанный выше CLI `inspect` и
возвращает его JSON-вывод; собственной логики получения данных из кластера в нём нет. В этом и суть:
**AI-агент, использующий этот адаптер, никогда не получает прямого доступа к кластеру** — ни
kubeconfig, ни реальные учётные данные API до самого агента не доходят, только stdout этого
процесса.

```sh
export KUBECONFIG=~/.kube/config
export KUBE_CONTEXT=my-context   # опционально
kubectl-audit-mcp
```

Он общается через newline-delimited JSON-RPC 2.0 поверх stdio — направьте любой MCP-совместимый
клиент (Claude Desktop, MCP inspector, вашу собственную инфраструктуру агентов) прямо на этот
бинарник. Предполагаемое использование в production — *эфемерное*: запускается рядом с тем
процессом, который выполняет сканирование (переиспользуя уже легитимный, уже ограниченный по
правам kubeconfig этого процесса только на время его работы), а не как постоянный sidecar с
собственными учётными данными — пока никуда автоматически не подключён, поскольку сегодня нет
оркестратора сканирований внутри кластера (см. «Регистрация кластера и отправка результатов
сканирования» выше: сканирование — это просто запуск `kubectl-audit scan`/`push` там, где удобно,
а не то, что инициирует сам сервер).

## Развёртывание в реальном кластере (Helm-чарт)

`charts/kubectl-audit-server` разворачивает Postgres (по умолчанию через оператор
[CloudNativePG](https://cloudnative-pg.io)), а также сам сервер и kubectl-audit-worker (цикл
оценки правил автоматизации, отдельный Deployment):

```sh
helm install audit charts/kubectl-audit-server \
  --namespace kubectl-audit-system --create-namespace \
  --set image.repository=<your-registry>/kubectl-audit-server --set image.tag=<tag>

kubectl -n kubectl-audit-system get secret audit-admin-token \
  -o jsonpath='{.data.token}' | base64 -d   # автоматически сгенерированный admin-токен
```

Варианты подключения существующего Postgres вместо CNPG см. в
`charts/kubectl-audit-server/README.md` — каждое значение описано в `values.yaml`.
