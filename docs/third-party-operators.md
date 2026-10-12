# Проверки сторонних операторов

Помимо [Capsule](./compliance.md) и [Istio](./istio.md), этот инструмент включает небольшой набор
проверок для других распространённых дополнений кластера — каждая прослеживается к конкретной,
процитированной строке официальной документации по безопасности соответствующего проекта,
сверена поле за полем с реальным исходным кодом CRD перед тем, как быть записанной в виде CEL, и
охватывает только то, что реально можно проверить по одному объекту CRD. Короткий список вместо
широкого охвата — осознанное решение: эти проекты не получают того же подхода "покрыть всё
реалистичное", что CIS/NSA/Capsule, поскольку ни для одного из них не существует сопоставимого
сквозного бенчмарка безопасности, от которого можно было бы отталкиваться.

Каждая проверка здесь выдаёт находки только если соответствующий CRD действительно присутствует в
скане — безвредна (ноль находок) на любом кластере, где это дополнение не используется. В режиме
живого кластера все эти CRD получаются путём определения реально обслуживаемой/предпочитаемой
версии каждой группы через собственное API-обнаружение кластера (см. `resolvePreferredVersion` в
`internal/loader/cluster.go`), а не версии, зашитой в этот инструмент — по тем же причинам, что
описаны в разделах про Capsule/Istio.

## Инвентаризация компонентов (`internal/thirdparty`)

Каждое сканирование также сверяет загруженные ресурсы с небольшим встроенным списком известных
сторонних компонентов (`internal/thirdparty/components.yaml`) и, если что-то обнаружено, выводит
раздел **Detected Components** ближе к началу `report.md`, перед самими находками. Это чисто
информационный раздел: он существует для того, чтобы читателю не приходилось гадать, *почему*
проверка сработала или не сработала, и чтобы сделать механизм исключений ниже аудируемым, а не
неявным.

Каждый известный компонент — это данные, а не Go-код: запись YAML с полями:

- `name` — отображаемое имя.
- `category` — `System` (требует доступа уровня хоста/ОС для выполнения своей работы — см. ниже)
  или `Application` (обычный CRD/оператор без доступа к хосту, проверяется в полную силу, без
  исключений).
- `group` — группа API CRD, однозначно подтверждающая, что компонент установлен, если он её
  поставляет (например, `cilium.io`, `capsule.clastix.io`). Это надёжный сигнал: группа CRD либо
  существует в кластере, либо нет — одинаково от кластера к кластеру, независимо от того, как кто
  промаркировал свои workload'ы.
- `labels` — селектор меток, сопоставляемый только с объектами Deployment/StatefulSet/DaemonSet
  (никогда с Namespace, ServiceAccount или другим объектом, который легко может пережить сам
  контроллер), идентифицирующий реальный workload контроллера/оператора/агента — например,
  `k8s-app: cilium`. Задан для каждого компонента с `group`, а не только для `System`: это то, что
  позволяет скану отличить "этот компонент действительно запущен" от "его CRD присутствуют", что
  важно по двум разным причинам — для компонентов `System` это определяет, *к какому объекту*
  должно применяться встроенное исключение (ниже); для любого компонента это ловит
  распространённый случай, когда CRD переживает свой контроллер (`helm uninstall` по умолчанию не
  удаляет CRD), что иначе привело бы к ложному отображению удалённого компонента как
  присутствующего.

Обнаружение также проверяет метку `app.kubernetes.io/managed-by: Helm` на сопоставленных объектах,
так что отчёт может указать, был ли компонент установлен через Helm — но не был ли через Helm
установлен тот контроллер, который его реконсилирует, поскольку этот сигнал не может подтвердить
такое утверждение.

Чтобы добавить новый компонент во *встроенный* инвентарь, отредактируйте `components.yaml` и
пересоберите проект — изменения в Go не требуются ни для одной из категорий. Добавление записи
`System` обычно также означает добавление соответствующего правила в `builtin-exclusions.yaml`
(следующий раздел); для записи `Application` больше ничего не нужно.

**Расширение без пересборки.** `components.yaml` (как и `builtin-exclusions.yaml`) компилируется в
бинарник через `go:embed` — на диске нет файла для редактирования, что важно, если вы установили
инструмент через krew: пересборка просто недоступна. Для ваших собственных внутренних
операторов/CNI добавляйте их прямо в `audit.yaml` — отдельный файл и пересборка не нужны:

```yaml
components:
  extra:
    - name: InternalWidgetOperator
      category: Application       # System | Application (default: Application)
      group: internal.example.com
      labels:
        app.kubernetes.io/name: internal-widget-operator
```

Та же схема, объединяется со встроенным списком во время сканирования
(`config.ComponentsConfig.Extra`). Это только добавляет запись в инвентарь/обнаружение
бесхозных объектов — само по себе это **не** создаёт исключение подавления; для этого добавьте к
записи категории `System` собственное правило `exclusions` (см.
[Конфигурация](./configuration.md)) — так же, как для любого встроенного компонента `System`.

### Встроенные исключения для привилегированной системной инфраструктуры

Часть инфраструктуры кластера — узловой агент CNI, экспортёр метрик — законно нуждается в
`hostNetwork`, монтировании `hostPath` или повышенных capabilities для выполнения своей задачи, и
в результате всегда будет нарушать профили Baseline/Restricted
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
Kubernetes. Простое исключение неймспейса (`kube-system`, `cilium-system`, ...) скрыло бы это — а
*заодно* скрыло бы и любой по-настоящему сломанный workload, который кто-то ещё запускает в том же
неймспейсе. Поэтому этот инструмент поставляется с небольшим, точным, подкреплённым источниками
набором встроенных правил исключения (`internal/suppress/builtin-exclusions.yaml`), включённым по
умолчанию и строго следующим двум правилам:

1. **Сопоставление по метке, никогда по неймспейсу.** Правило подавляет находки только на
   конкретном объекте (объектах), соответствующем селектору меток для этого точного компонента
   (например, `k8s-app: cilium`) — где бы в кластере он ни находился.
2. **Ограничено точным, подкреплённым источниками набором `policyIds`**, которые собственная
   документация апстрима этого компонента (сверенная с реальным исходным кодом Helm-чарта, а не
   предполагаемая) называет необходимыми — никогда не сплошное подавление. Любая другая проверка —
   RBAC, лимиты ресурсов, фиксация тегов образов и любая проверка PSS/workload, *не входящая* в
   этот известный набор — по-прежнему выполняется в полную силу против того же объекта.

Текущее покрытие:

| `id` | Компонент | Подавляемые проверки | Источник |
|---|---|---|---|
| `cilium-agent` | Агент Cilium (`k8s-app: cilium`) | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline`, `pss-analyzer.restricted` | [cilium-agent daemonset.yaml / values.yaml](https://github.com/cilium/cilium/blob/main/install/kubernetes/cilium/templates/cilium-agent/daemonset.yaml) — hostNetwork, монтирование hostPath для BPF/cgroup, capabilities — каждая обоснована отдельно (например, `NET_ADMIN` "используется, так как cilium изменяет таблицы маршрутизации"). cilium-operator — отдельный, непривилегированный компонент и этим покрытием **не** охватывается. |
| `prometheus-node-exporter` | prometheus-node-exporter (`app.kubernetes.io/name: prometheus-node-exporter`) | `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `pss-analyzer.baseline`, `pss-analyzer.restricted` | [prometheus-node-exporter daemonset.yaml / values.yaml](https://github.com/prometheus-community/helm-charts/blob/main/charts/prometheus-node-exporter/templates/daemonset.yaml) — hostNetwork, hostPID, монтирование `/proc`/`/sys`/`/` только для чтения. Не привилегирован, не добавляет capabilities, поэтому `workload.no-privileged-containers`/`workload.drop-all-capabilities` для него намеренно **не** подавляются — используется одинаково под Prometheus, VictoriaMetrics или Thanos. |
| `falco` | Агент Falco (`app.kubernetes.io/name: falco`) | `workload.no-privileged-containers`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | [falco daemonset.yaml](https://github.com/falcosecurity/charts/blob/master/charts/falco/templates/daemonset.yaml) — привилегирован (для загрузки своего драйвера ядра/eBPF-зонда) плюс необычно большой набор hostPath (сокеты container runtime, `/proc`, `/etc`, `/dev`, `/sys/module`, `/sys/kernel`, `/lib/modules`, `/boot`). Не использует hostNetwork/hostPID, не задаёт seccomp и не запускается от non-root, поэтому эти проверки для него **не** подавляются. |
| `tetragon` | Агент Tetragon (`app.kubernetes.io/name: tetragon`) | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | [tetragon daemonset.yaml](https://github.com/cilium/tetragon/blob/main/install/kubernetes/tetragon/templates/daemonset.yaml) — hostNetwork, privileged, монтирование `/sys/fs/bpf` + `/proc` + hostPath состояния среды выполнения Cilium. tetragon-operator — отдельный, непривилегированный, non-root компонент и этим покрытием **не** охватывается. Профиль seccomp не задан, поэтому `pss-analyzer.restricted` **не** подавляется. |
| `kube-proxy` | kube-proxy (`k8s-app: kube-proxy`) — часть ядра Kubernetes, не сторонний компонент | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | Собственный стандарт kubeadm, оригинальный отрендеренный манифест — проверено напрямую на живом кластере, развёрнутом через kubeadm (hostNetwork, `privileged: true`, монтирование hostPath `/run/xtables.lock` и `/lib/modules`). Отсутствие профиля seccomp и запуск от root не связаны с этим требованием и остаются помеченными (`pss-analyzer.restricted`, `workload.run-as-non-root` **не** подавляются). |
| `control-plane-static-pods` | Статические поды control-plane — `kube-apiserver`/`kube-controller-manager`/`kube-scheduler`/`etcd` (`tier: control-plane`) — часть ядра Kubernetes, не сторонний компонент | `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `pss-analyzer.baseline` | Модель статических подов kubeadm — проверено напрямую на живом кластере, развёрнутом через kubeadm (hostNetwork, hostPath-монтирование `/etc/kubernetes/pki` и каталогов данных компонентов). Актуально только для самоуправляемого control-plane/kubeadm — управляемый control-plane (EKS/GKE/AKS) вообще никогда не представляет их как Pod'ы. Усиление в части non-root/capabilities/seccomp/ServiceAccount по умолчанию не связано с этим требованием и остаётся помеченным. |

Последние две строки — не сторонний софт, поэтому у них нет записи в
`internal/thirdparty/components.yaml` и они не появляются в таблице Detected Components — это
обычные правила исключения, тот же механизм, просто не "обнаруженная инфраструктура" в том
смысле, в котором рассматривает её остальная часть этой страницы.

Подавленные находки никогда не скрываются полностью — они по-прежнему отображаются в разделе
отчёта **Suppressed Findings** вместе с причиной (включая ссылку на источник), точно так же, как и
правило `exclusions`, заданное пользователем, потому что это им и является: поставляемая,
курируемая заготовка того же механизма (см. [Конфигурация: exclusions](./configuration.md)).

**Обнаружение только по CRD.** Поскольку селектор меток — единственная часть этого механизма,
которая действительно может отличаться от кластера к кластеру, или просто перестать что-либо
находить после удаления компонента (`helm uninstall` по умолчанию не удаляет CRD, поэтому старые
CRD/CR нередко переживают создавший их контроллер) — каждое сканирование дополнительно сверяет его
с сигналом группы CRD, для каждого компонента в инвентаре, а не только для тех, у кого есть
встроенное исключение. Если группа CRD компонента присутствует, но ни один
Deployment/StatefulSet/DaemonSet не совпал с его селектором меток, раздел отчёта **Scope** получает
явную оговорку с именем компонента, ссылкой на `components.yaml` и описанием обеих вероятных
причин. Если вы видите эту оговорку: либо в вашей установке используются нестандартные метки
(добавьте собственное правило `exclusions`, совпадающее с ними — это актуально, только если
помеченный компонент относится к `System`), либо компонент был удалён, а его CRD/CR остались
(любые находки по этим устаревшим объектам тогда касаются конфигурации, которую уже не применяет
никакой контроллер) — либо это ожидаемо и безопасно проигнорировать.

Чтобы отключить все встроенные исключения для более строгого сканирования, показывающего буквально
всё: `--no-builtin-exceptions` / `disableBuiltinExceptions: true`. Чтобы отключить только одно
(например, видеть всё, что связано с Cilium, но сохранить исключение для kube-proxy), отключите его
по `id` из таблицы выше: `--disable-builtin-exception-id cilium-agent` /
`disableBuiltinExceptionIds: [cilium-agent]` в `audit.yaml` — отдельный файл редактировать не нужно,
работает одинаково независимо от того, собрали вы инструмент из исходников или установили через
krew.

## ArgoCD (`argoproj.io/v1alpha1` — без истории версий, никогда не продвигалась)

Три проверки на `AppProject`, собственной границе тенантности/RBAC ArgoCD
([документация user-guide/projects](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/)).
Примечание: встроенный `default` AppProject самой ArgoCD поставляется именно с такими wildcard'ами —
находка здесь часто означает "всё ещё используется проект по умолчанию", а не экзотическую
неправильную конфигурацию.

- `argocd.appproject-wildcard-source-repos` (Medium) — `spec.sourceRepos` включает `"*"`.
- `argocd.appproject-wildcard-destinations` (High) — запись `spec.destinations` имеет одновременно
  `namespace: "*"` и `server`/`name: "*"`.
- `argocd.appproject-wildcard-cluster-resources` (High) — `spec.clusterResourceWhitelist` включает
  `{group: "*", kind: "*"}`.
- `argocd.application-uses-default-project` (Medium) — `Application.spec.project` не задан или
  равен `"default"`. Собственная [документация projects](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/)
  ArgoCD: "Проект `default` можно изменить, но нельзя удалить. ... рекомендуется создавать
  выделенные проекты с явными разрешениями на источники, назначения и ресурсы." Складывается с
  тремя проверками wildcard выше: Application здесь наследует всё, что на данный момент разрешает
  AppProject по умолчанию.
- `argocd.rbac-cm-default-admin-policy` (High) — в ConfigMap `argocd-rbac-cm` поле
  `data['policy.default']` равно `"role:admin"`. Собственная [документация RBAC](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/)
  ArgoCD: "Когда пользователь аутентифицирован в Argo CD, ему будет предоставлена роль, указанная в
  `policy.default`. ... Все аутентифицированные пользователи получают *как минимум* разрешения,
  предоставляемые политиками по умолчанию. Этот доступ нельзя заблокировать правилом `deny`. ...
  Рекомендуется создать новую роль `role:authenticated` с минимально необходимым набором
  разрешений." Без CRD — сопоставляется по собственной, стабильной по имени идентичности ConfigMap
  (`argocd-rbac-cm`), тот же паттерн, что и для проверок Airflow/APISIX ниже.
- `argocd.cmd-params-cm-server-insecure` (Medium) — в ConfigMap `argocd-cmd-params-cm` поле
  `data['server.insecure']` равно `"true"`. Собственный [справочник параметров времени выполнения](https://argo-cd.readthedocs.io/en/stable/operator-manual/argocd-cmd-params-cm-yaml/)
  ArgoCD: `server.insecure` — "Запускать сервер без TLS". Это собственный документированный,
  поддерживаемый паттерн ArgoCD специально для случая, когда внешний прокси/ingress терминирует TLS
  (документация рекомендует это для Ambassador, Contour, NGINX, GKE, ...) — но документация не
  предупреждает отдельно против установки этого значения без такого прокси. Тот же паттерн с
  содержимым ConfigMap, что и `argocd.rbac-cm-default-admin-policy`, проверяющий собственный
  объект конфигурации времени выполнения компонента, а не CRD.
- `argocd.cmd-params-cm-disable-auth` (Critical) — в `argocd-cmd-params-cm` поле
  `server.disable.auth` равно `"true"`. Проверено напрямую по официальному справочнику
  ([argocd-cmd-params-cm.yaml](https://github.com/argoproj/argo-cd/blob/master/docs/operator-manual/argocd-cmd-params-cm.yaml)):
  `` # Disable client authentication / server.disable.auth: "false" ``. Полностью отключает
  собственную аутентификацию ArgoCD — аналог KubeVirt-овского feature gate `Root` для ArgoCD.
- `argocd.cmd-params-cm-repo-server-oob-symlinks-allowed` (High) —
  `reposerver.allow.oob.symlinks` равен `"true"`. Тот же справочник, процитирован полностью:
  "Разрешить репозиториям содержать символические ссылки, выходящие за границы репозитория.
  Изменение этого значения на \"true\" не разрешит *все* символические ссылки за пределами границ.
  Они по-прежнему будут блокироваться, например, для values-файлов в Helm-чартах. Но символические
  ссылки, не заблокированные другими явными проверками, будут разрешены." По умолчанию `"false"`.
- `argocd.cmd-params-cm-internal-tls-disabled` (Medium) — любой из параметров
  `reposerver.disable.tls`, `dexserver.disable.tls`, `controller.repo.server.plaintext`,
  `server.repo.server.plaintext`, `server.dex.server.plaintext`,
  `notificationscontroller.repo.server.plaintext` равен `"true"`. Тот же справочник; каждый по
  умолчанию `"false"` и отключает TLS между двумя компонентами ArgoCD, взаимодействующими внутри
  кластера. Ключи `*.strict.tls` намеренно **не** охватываются — по умолчанию они равны `"false"`
  (нестрогий режим) сразу после установки, поэтому их проверка срабатывала бы на каждой
  неизменённой установке; это не понижение уровня защиты, инициированное оператором.
- `argocd.application-sync-validate-disabled` (Medium) — `Application.spec.syncPolicy.syncOptions`
  включает `"Validate=false"`. Собственная документация ArgoCD по опциям синхронизации описывает
  это как пропуск проверки схемы ресурсов kubectl во время синхронизации (функциональный эквивалент
  `kubectl apply --validate=false`). Источник слабее, чем у большинства проверок здесь
  (отключение документированного механизма безопасности, а не явное предупреждение "небезопасно") —
  тот же уровень, что и `istio.gateway-weak-tls-version`.
- `argocd.redis-requirepass-missing` (Critical) — у контейнера `redis` Deployment'а
  `argocd-redis` нет флага `--requirepass`. Это [CVE-2024-31989 / GHSA-9766-5277-j5hr](https://github.com/argoproj/argo-cd/security/advisories/GHSA-9766-5277-j5hr):
  "По умолчанию сервер базы данных Redis не защищён паролем, что позволяет злоумышленнику с
  доступом к серверу Redis получить доступ на чтение/запись к данным в Redis" — этого достаточно,
  чтобы заставить ArgoCD применять произвольные ресурсы, изменив ключ кэшированного манифеста, или
  утечь ресурсы через ключ кэшированного дерева ресурсов. Исправлено в ArgoCD 2.11.1/2.10.10/
  2.9.15/2.8.19+, которые по умолчанию поставляются со сгенерированным паролем (проверено по
  официальному манифесту: аргументы контейнера redis теперь всегда включают
  `--requirepass $(REDIS_PASSWORD)`). Срабатывает на неисправленной версии или на пользовательском
  манифесте, из которого этот флаг был убран. Ограничено хорошо известным именем Deployment
  non-HA-топологии `argocd-redis`; отдельная HA-топология ArgoCD (`argocd-redis-ha`, Sentinel за
  HAProxy) использует совершенно другую форму манифеста и этой проверкой **не** охватывается —
  известный пробел.

Не проверяется: `Application.spec.syncPolicy.automated.prune`/`selfHeal` — действительно ли
автоматическая синхронизация с prune опасна, зависит от области действия владеющего AppProject
(проверки выше) — это межобъектное рассуждение, выходящее за рамки того, что может честно
утверждать проверка на основе одного объекта VAP. Также не проверяются опции синхронизации
`Prune=false`/`Replace=true`/`Force=true`/`SkipDryRunOnMissingResource=true` — реальные и
документированные ArgoCD как рискованные ("деструктивные", "могут вызвать простой"), но это вопрос
доступности/эксплуатационной безопасности, а не конфиденциальности/целостности — вне сферы
безопасности этого инструмента, без утверждения, что это безопасно.

## HashiCorp Vault Secrets Operator (`secrets.hashicorp.com/v1beta1`)

- `vault.connection-skip-tls-verify` (High) — `VaultConnection.spec.skipTLSVerify: true`.
  Собственная [модель угроз](https://github.com/hashicorp/vault-secrets-operator/blob/main/docs/threat-model/README.md)
  VSO прямо утверждает: "Используйте TLS, согласованный доверенным центром сертификации, для всей
  сетевой коммуникации, особенно для Vault и Kubernetes API."
- `vault.auth-allowed-namespaces-wildcard` (High) — `VaultAuth.spec.allowedNamespaces` включает
  `"*"`. Собственный справочник CRD `VaultAuth` VSO: "AllowedNamespaces — неймспейсы Kubernetes,
  внесённые в список разрешённых для использования с этим AuthMethod. ... `[]{"*"}` — wildcard, все
  неймспейсы. ... если не задано — запретить все неймспейсы, кроме ... неймспейса самого
  VaultAuthMethod, это поведение по умолчанию." Wildcard позволяет любому неймспейсу-тенанту
  аутентифицироваться через роль/политику Vault этого метода — та же проблема пересечения границ
  тенантов, что и в проверках wildcard AppProject ArgoCD выше.

## Capsule (`capsule.clastix.io` — мультитенантность)

Проверки находятся под префиксом policy ID `multitenancy.*`, а не `capsule.*` (соглашение этого
репозитория: категория описывает суть проблемы, а не просто вендора). Восемь ранее существовавших
проверок (`multitenancy.capsule-tenant-cluster-admin-binding`, `-no-limit-range`,
`-no-image-pull-policy-restriction`, `-no-network-policies`, `-no-node-isolation`,
`-no-registry-allowlist`, `-no-psa-enforcement`, `-no-resource-quota`) охватывают поверхность
принуждения `Tenant` в Capsule — источник каждой проверки см. в её собственной аннотации
`audit.k8s-auditor.io/remediation`, здесь не дублируется.

- `multitenancy.capsule-tenant-owner-cluster-admin-role` (High) — `Tenant.spec.owners[].clusterRoles`
  включает `"cluster-admin"` (по умолчанию `{admin, capsule-namespace-deleter}`). Проверено
  напрямую по собственному исходному коду Capsule (`pkg/api/rbac/owner.go`, комментарий к полю
  `CoreOwnerSpec.ClusterRoles`): "Определяет дополнительные cluster-роли для конкретного Owner" —
  Capsule синхронизирует RoleBinding для каждой из них в каждый неймспейс, принадлежащий тенанту.
  Отличается от `multitenancy.capsule-tenant-cluster-admin-binding`, которая проверяет только
  `spec.additionalRoleBindings` — эта проверка смотрит на отдельное поле `spec.owners[]`. Тот же
  лежащий в основе риск: субъект тенанта с `cluster-admin` полностью нарушает изоляцию тенантов.

Исследовано и отклонено в рамках этого прохода (API Capsule в основном состоит из разрешительных
списков с opt-in, которые являются permissive *когда не заданы* — обратная ситуация по сравнению с
"явным понижением защиты"; большинство реальных пробелов здесь относится к проверкам типа
"отсутствует усиление защиты", что отличается от паттерна, на который был нацелен этот проход):
- `spec.serviceOptions.allowedServices.{nodePort,loadBalancer,externalName}` — реальные поля, и
  собственный комментарий к полю `externalName` действительно говорит, что "сервисы типа
  ExternalName несут риски безопасности", но значение по умолчанию — `true` (разрешено) — здесь нет
  момента явного opt-in, только состояние "отсутствие уже небезопасно". Стоит рассмотреть в будущем
  проходе с другим подходом, не в этом.
- `spec.podOptions` — проверено по исходному коду: содержит только `AdditionalMetadata`
  (метки/аннотации), нет полей, относящихся к безопасности.
- `spec.storageClasses`/`spec.runtimeClasses`/`spec.priorityClasses`
  (`DefaultAllowedListSpec`) — та же форма "permissive, когда не задано", что и у
  `allowedServices`; отдельного значения-признака wildcard-разрешения не найдено.

## Fluent Operator (`fluentbit.fluent.io/v1alpha2`)

- `fluentbit.output-tls-not-verified` (High) — у назначения `Output`/`ClusterOutput` типа `http`,
  `es` (Elasticsearch), `forward`, `splunk`, `loki`, `influxDB`, `opensearch`, `opentelemetry`,
  `prometheusRemoteWrite`, `syslog`, `tcp` или `gelf` нет `tls.verify: true`. Собственная
  [документация по транспортной безопасности](https://docs.fluentbit.io/manual/3.1/administration/transport-security)
  Fluent Bit гласит: "всегда держите проверку [TLS] включённой в production" — каждый из этих типов
  назначения иначе по умолчанию использует открытый текст. Все двенадцать проверены поле за полем
  по исходному коду Go [github.com/fluent/fluent-operator](https://github.com/fluent/fluent-operator)
  (и точным json-тегам родительской спецификации — например, `influxDB`, `opensearch`, а не
  `open_search`, `prometheusRemoteWrite`, а не `prometheus_remote_write` — и файлу типа каждого
  плагина): каждый встраивает идентичную структуру `plugins.TLS`. `kafka` намеренно **не**
  охватывается: он использует сырые свойства `rdkafka` вместо этого, без эквивалентного поля для
  проверки. `datadog` тоже не охватывается: его поле `TLS` — это обычный `*bool` ("использовать TLS
  вообще", а не "проверять сертификат") — другая семантика, не та же проверка.

## VictoriaMetrics Operator (`operator.victoriametrics.com/v1beta1`)

- `victoriametrics.no-delete-auth-key` (Medium) — у `VMSingle`/`VMCluster` в `spec.extraArgs` нет
  `deleteAuthKey`, из-за чего `/api/v1/admin/tsdb/delete_series` остаётся доступным без ключа. Это
  одна из нескольких допустимых мер, документированных VictoriaMetrics (прокси `vmauth`/`vmgateway`
  перед сервисом или NetworkPolicy покрывают тот же пробел) — находка здесь означает, что
  отсутствует конкретно этот уровень защиты, а не что эндпоинт подтверждённо доступен атакующему.
- `victoriametrics.vmauth-unauthorized-access-wildcard-path` (High) — в
  `VMAuth.spec.unauthorizedUserAccessSpec.url_map[]` есть запись `src_paths`, совпадающая со всем
  (например, `".*"`). Собственная [документация](https://docs.victoriametrics.com/victoriametrics/vmauth/)
  VMAuth: "Запросы без заголовка Authorization проксируются согласно разделу
  `unauthorized_user`" — и этот раздел "имеет приоритет при обработке маршрута без учётных данных,
  даже если такой маршрут также существует в разделе users". Wildcard здесь направляет каждый
  неаутентифицированный запрос на бэкенд этого правила, независимо от любой настроенной иначе
  аутентификации по пользователю в том же `VMAuth`. Примечание: `url_map`/`url_prefix` считаются
  устаревшими начиная с оператора v0.67.0 в пользу `spec.unauthorizedUserAccessSpec.targetRefs`
  (удаление запланировано на v0.69.0, согласно собственной аннотации `+notes` CRD) — эта проверка
  охватывает только старую, пока ещё поддерживаемую форму.
- `victoriametrics.vmagent-remotewrite-tls-insecure-skip-verify` (High) —
  `VMAgent.spec.remoteWrite[].tlsConfig.insecureSkipVerify: true`. Проверено напрямую по
  собственному исходному коду оператора на Go (`api/operator/v1beta1/vmextra_types.go`, комментарий
  к полю `TLSConfig.InsecureSkipVerify`): "Отключить проверку сертификата цели." Назначение
  remote write с отключённой проверкой сертификата уязвимо к MITM — каждая метрика, которую
  собирает и пересылает этот VMAgent, может быть перенаправлена или перехвачена. Проверяется
  только `VMAgent`; `VMAlert`/`VMAuth` используют тот же общий тип `TLSConfig` на собственных полях
  notifier/backend — пока не охвачено, известный пробел.
- `victoriametrics.vmauth-select-all-by-default-enabled` (Medium) —
  `VMAuth.spec.selectAllByDefault: true`. Собственный комментарий к полю оператора VictoriaMetrics
  (`api/operator/v1beta1/vmauth_types.go`): "изменяет поведение по умолчанию для пустых селекторов
  CRD... при selectAllByDefault: true и пустых userSelector и userNamespaceSelector оператор
  выбирает всех существующих пользователей." Явный отказ от границ доверия, разграниченных по
  неймспейсу/меткам — та же форма, что и `vault.auth-allowed-namespaces-wildcard`. Источник слабее,
  чем у большинства проверок здесь (нет явного предупреждения "небезопасно" от самой
  VictoriaMetrics, тот же уровень, что и `istio.gateway-weak-tls-version`).

Исследовано и отклонено, с указанием фактической меры по снижению риска:
- Учётные данные уведомителя/вебхука VMAlert/VMAlertmanager в обычном случае передаются через
  ссылки `SecretKeySelector`, а не как открытый текст в полях CRD — если когда-нибудь значение всё
  же попадёт в ConfigMap, этот паттерн уже покрывается общей проверкой этого инструмента
  `secrets.configmap-no-embedded-credentials`, независимо от того, в ConfigMap какого продукта оно
  появилось.

## CloudNativePG (`postgresql.cnpg.io/v1` — без истории версий, никогда не продвигалась)

- `cnpg.cluster-superuser-access-enabled` (High) — `Cluster.spec.enableSuperuserAccess: true`.
  Собственная [документация по безопасности](https://cloudnative-pg.io/documentation/current/security/)
  CNPG утверждает, что когда это значение равно `false` (по умолчанию), "оператор удаляет
  сгенерированные секреты и устанавливает пароль пользователя postgres в NULL, предотвращая
  удалённый доступ через парольную аутентификацию" — единственное документированное правильное
  значение, а не ситуативное суждение.
- `cnpg.cluster-monitoring-tls-disabled` (Medium) — `Cluster.spec.monitoring.tls.enabled` не равно
  `true`. Собственная [документация по мониторингу](https://cloudnative-pg.io/docs/devel/monitoring/)
  CNPG: "Чтобы включить TLS-соединение на порту метрик, установите параметр
  `.spec.monitoring.tls.enabled` в `true`. Эта настройка гарантирует, что экспортёр метрик
  использует тот же серверный сертификат, что и PostgreSQL для защиты соединения на порту 5432."
  По умолчанию `false` согласно реальной схеме CRD, поэтому эндпоинт метрик (статистика Postgres,
  не учётные данные) по умолчанию работает по обычному HTTP.

Исследовано и отклонено, с указанием фактической меры по снижению риска:
- `spec.postgresql.pg_hba` может содержать строки с аутентификацией `trust`, но собственная
  документация CNPG прямо описывает это как часть *предполагаемой* модели доверия для того, кто
  уже имеет доступ на запись к объекту `Cluster`. **Уже смягчено**: это вопрос границы RBAC,
  который уже покрывается общими проверками `rbac-analyzer.*` этого инструмента, а не
  самостоятельная неправильная конфигурация CNPG.
- Собственный Deployment оператора CNPG (`cnpg-controller-manager`) полностью усилен самим CNPG
  "из коробки" (`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `readOnlyRootFilesystem: true`, non-root, лимиты ресурсов — проверено по реальному манифесту
  установки). **Уже смягчено**: любая регрессия здесь улавливается общими проверками `workload.*`
  этого инструмента, как и для любого другого Deployment.
- Собственные admission-вебхуки оператора (`cnpg-mutating-webhook-configuration`/
  `cnpg-validating-webhook-configuration`) поставляются с жёстко заданным `failurePolicy: Fail` без
  переключателя, доступного через чарт, чтобы его ослабить — в отличие от
  `--forceFailurePolicyIgnore` у Kyverno, здесь нечего проверять; значение фиксировано, а не
  настраиваемо.
- `Pooler.spec.pgbouncer.parameters.client_tls_sslmode`/`server_tls_sslmode`/`auth_type` —
  реальные поля, но документация CNPG не выделяет одно значение как *то самое*
  документированно-безопасное, в отличие от `enableSuperuserAccess`/TLS мониторинга — у sslmode
  PgBouncer несколько законных уровней, а `auth_type: hba` — это собственное заявленное значение по
  умолчанию CNPG, а не небезопасное. Недостаточно обосновано как правильное/неправильное; отклонено
  на тех же основаниях, что и `insecureSkipVerify` VictoriaMetrics выше.
- `spec.automountServiceAccountToken` (автомонтирование токена ServiceAccount на подах/Job
  инстанса) — актуальная документация CNPG (`docs/src/security.md`) всё ещё показывает это как
  пользовательски настраиваемое поле `Cluster.spec` с примером YAML, но на самом деле такого поля
  не существует: проверено напрямую по `ClusterSpec` в `api/v1/cluster_types.go` и
  сгенерированной схеме CRD (как текущий релиз, так и `main`) — такого поля нет ни в одной версии.
  Документация устарела: открытый (на момент написания не влитый) апстрим-PR
  [#11297](https://github.com/cloudnative-pg/cloudnative-pg/pull/11297) объясняет причину — опциональное
  поле было **удалено** в пользу безусловного поведения оператора
  ([#11115](https://github.com/cloudnative-pg/cloudnative-pg/pull/11115), "всегда отключать
  автомонтирование токена сервисного аккаунта"): CNPG теперь отключает автомонтирование на каждом
  поде инстанса, Job инициализации БД и сгенерированном ServiceAccount **безусловно**, без поля,
  которое пользователь мог бы неправильно настроить. **Уже смягчено, сильнее, чем могла бы любая
  проверка этого инструмента**: поведение гарантируется самим оператором, а не чем-то, что нужно
  проверять сканированием для каждого Cluster.

## Strimzi (`kafka.strimzi.io/v1` — после консолидации CRD с `v1beta2`)

- `strimzi.kafka-no-authorization-configured` (High) — `Kafka.spec.kafka.authorization` не задано.
  Проверено напрямую по реальной схеме CRD (`install/cluster-operator/040-Crd-kafka.yaml`): поле
  полностью опционально и передаётся напрямую в конфигурацию собственного авторизатора брокера —
  без настроенного авторизатора поведение Kafka по умолчанию — разрешить любую операцию любому
  клиенту, без каких-либо ACL-границ вообще.
- `strimzi.kafka-external-listener-tls-disabled` (High) — запись `Kafka.spec.kafka.listeners`, чей
  `type` не равен `internal` (`route`/`tlsroute`/`loadbalancer`/`nodeport`/`ingress`/`cluster-ip`
  — все они доступны к брокеру извне сети подов кластера), имеет `tls`, не равный `true`. `tls` —
  обязательное поле для каждого listener'а (проверено по схеме), поэтому это всегда явное `false`,
  никогда не пропуск значения.
- `strimzi.kafka-external-listener-no-authentication` (High) — та же область действия внешнего
  listener'а, что и выше, но `authentication` вообще не задан: любой клиент, способный достучаться
  до listener'а, может подключиться без каких-либо учётных данных (только отдельно проверяемый
  `spec.kafka.authorization` может всё же ограничить, что разрешено неаутентифицированному
  клиенту).
- `strimzi.kafkauser-acl-wildcard-topic-access` (High) — правило `allow` в
  `KafkaUser.spec.authorization.acls` имеет `resource.type: topic`, `resource.name: "*"`,
  `patternType: literal` (значение по умолчанию). Буквальное имя ресурса `"*"` — это собственное,
  хорошо известное соглашение Kafka для ACL-wildcard'ов (`ResourcePattern` с `PatternType.LITERAL`
  и именем `"*"` соответствует каждому ресурсу этого типа), а не общий глоб — это правило
  предоставляет указанные операции по отношению ко всем топикам в кластере, включая те, что будут
  созданы позже.

Обнаружение компонента (`internal/thirdparty/components.yaml`) сопоставляется с собственной меткой
Deployment'а `strimzi-cluster-operator` `app: strimzi`, проверено по реальному манифесту установки
(`install/cluster-operator/060-Deployment-strimzi-cluster-operator.yaml` в
strimzi/strimzi-kafka-operator) — а не по метке `strimzi.io/kind: cluster-operator`, которая
присутствует только в шаблоне пода и по которой этот инструмент не сопоставляет (см.
[Инвентаризация компонентов](#инвентаризация-компонентов-internalthirdparty) выше: сопоставление
идёт по собственным `metadata.labels` объекта, а не по его шаблону пода).

## Kyverno (`kyverno.io/v1` ClusterPolicy/Policy)

- `kyverno.policy-validation-not-enforced` (Medium) — у политики как минимум с одним правилом
  `validate` поле `spec.validationFailureAction` не задано или равно `"Audit"`. Собственная
  [документация по настройкам политик](https://kyverno.io/docs/policy-types/cluster-policy/policy-settings/)
  Kyverno: `Audit` "разрешает запрос admission review и сообщает о нарушении политики в отчёте о
  политике" вместо того, чтобы блокировать его — и поле "по умолчанию равно `Audit`", если вообще
  не задано, так что незаданное значение действует точно так же необлокирующе, как и явно
  заданное. Политики, содержащие только правила `mutate`/`generate`/`verifyImages` (без правила
  `validate`), пропускаются — это поле на них не влияет.
- `kyverno.admission-controller-force-failure-policy-ignore` (High) — контейнер работает с флагом
  `--forceFailurePolicyIgnore=true`. Собственная
  [документация по установке/настройке](https://kyverno.io/docs/installation/customization/)
  Kyverno: этот флаг "задан, чтобы принудительно установить Failure Policy в `Ignore`" —
  переопределяя собственное `spec.failurePolicy` (по умолчанию `Fail`) каждой отдельной политики на
  уровне всего кластера, так что если сам Kyverno станет недоступен, каждый admission-запрос по
  всему кластеру будет пропущен без проверки, а не заблокирован. Конфигурация пода, не поле CRD —
  проверяется по аргументам контейнера Deployment'а `kyverno-admission-controller`, так же, как
  любая другая проверка workload читает конфигурацию контейнера, отличается лишь характерным
  названием этого флага.
- `kyverno.cluster-policy-admission-disabled` (High) — `spec.admission: false`. Проверено напрямую
  по собственному исходному коду Kyverno (`api/kyverno/v1/spec_types.go`, комментарий к полю
  `Admission`): "управляет тем, применяются ли правила во время admission... Значение по умолчанию
  — \"true\"." Политика с этим значением по-прежнему существует и выглядит активной, но полностью
  бездействует в момент admission — та же форма "выглядит активной, но на самом деле бесшумно нет",
  что и у `kubevirt.root-feature-gate-enabled`.
- `kyverno.cluster-policy-failure-policy-ignore` (Medium) — либо `spec.failurePolicy` (устаревшее,
  но всё ещё работающее), либо `spec.webhookConfiguration.failurePolicy` равно `"Ignore"`.
  Проверено напрямую по собственному исходному коду Kyverno (`api/kyverno/v1/common_types.go`,
  комментарий к полю `WebhookConfiguration.FailurePolicy`): "Допустимые значения — Ignore или Fail.
  По умолчанию Fail." Аналог на уровне отдельной политики для
  `kyverno.admission-controller-force-failure-policy-ignore` (которая отслеживает флаг контейнера
  на уровне всего admission-controller'а) — эта проверка отслеживает то же самое понижение защиты
  до fail-open, установленное на отдельном объекте политики.
- Не проверяется: установка `spec.validationFailureAction`/
  `spec.rules[*].validate[*].failureAction` в `Audit` как сигнал "понижения защиты" поверх уже
  существующей проверки `kyverno.policy-validation-not-enforced` — `Audit` является собственным
  документированным *значением по умолчанию* Kyverno, поэтому отдельная проверка на "явно
  установлено в Audit" срабатывала бы на подавляющем большинстве реальных ClusterPolicy; уже
  покрывается существующей проверкой независимо от того, задано ли значение явно или унаследовано.
  `background: false`/`skipBackgroundRequests` — они управляют фоновым *сканированием* (обнаружение
  дрейфа конфигурации у существующих ресурсов), а не принудительным применением во время admission;
  их отключение не пропускает ничего нового.
- Не проверяется: объекты `PolicyException` (которые позволяют сопоставленным ресурсам обходить
  конкретные политики). Собственная документация Kyverno называет узкое область действия "лучшей
  практикой", но судить, является ли конкретный `spec.match` "слишком широким", — не единый
  документированный порог, который этот инструмент может проверить без догадок — тот же критерий,
  по которому этот список остаётся коротким в других местах.

## Apache Airflow (без CRD — проверка содержимого ConfigMap)

- `airflow.webserver-expose-config-enabled` (Medium) — отрендеренный `airflow.cfg` (ключ данных
  ConfigMap, а не типизированное поле — у Airflow нет собственного CRD) устанавливает
  `expose_config = True`. Собственный
  [справочник конфигурации](https://airflow.apache.org/docs/apache-airflow/stable/configurations-ref.html)
  Airflow: `expose_config` — "Показывать файл конфигурации в веб-сервере[.] Установите `True`,
  чтобы показывать конфигурацию с всегда замаскированными чувствительными значениями[.] ... `False`
  полностью скрывает конфигурацию" — по умолчанию `False`. В текущей версии Airflow чувствительные
  значения маскируются, но имена хостов, пути и другие настройки всё равно раскрываются любому
  аутентифицированному пользователю — явное отклонение от безопасного значения по умолчанию.
- `airflow.webserver-config-auth-role-public` (Critical) — отрендеренный `webserver_config.py`
  (ключ данных ConfigMap, рендерится только если пользователь задаёт
  `apiServer.apiServerConfig`/`webserver.webserverConfig` в официальном Helm-чарте — безвреден/ноль
  находок в обычном случае, когда кластер его не настраивает отдельно) устанавливает
  `AUTH_ROLE_PUBLIC` в непустую роль. Собственная
  [документация](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/webserver-authentication.html)
  Airflow: "Чтобы отключить аутентификацию и позволить идентифицировать пользователей как
  Anonymous, следующая запись в `$AIRFLOW_HOME/webserver_config.py` должна быть установлена в роль,
  которую пользователь Anonymous будет получать по умолчанию: `AUTH_ROLE_PUBLIC = 'Admin'`" — это
  собственный документированный механизм Airflow для полного отключения аутентификации,
  по-прежнему актуальный в текущем Airflow 3.x (чей `auth_manager` по умолчанию всё ещё основан на
  Flask-AppBuilder).
- `airflow.hide-sensitive-var-conn-fields-disabled` (High) — параметр `[core]
  hide_sensitive_var_conn_fields` в `airflow.cfg` равен `False`. Собственный справочник
  конфигурации Airflow: "Скрывать чувствительные Variables или дополнительные json-ключи Connection
  из UI и логов задач при значении `True`", по умолчанию `True`. Пароли соединений (Connection)
  всегда скрыты независимо от этого (согласно той же документации) — это контролирует только
  дополнительные JSON-ключи и Variables, но в них тоже регулярно хранятся секреты.
- `airflow.api-auth-backend-default-enabled` (Critical) — параметр `[api] auth_backends` в
  `airflow.cfg` включает `airflow.api.auth.backend.default`. Это собственный справочник
  конфигурации Airflow 2.x, процитирован дословно: `("airflow.api.auth.backend.default" allows all
  requests for historic reasons)` ("...разрешает все запросы по историческим причинам"). Это
  собственная документация Airflow, утверждающая её же словами, что этот бэкенд предоставляет
  неаутентифицированный доступ к REST API — тот же уровень серьёзности, что и
  `airflow.webserver-config-auth-role-public`. Примечание: этот ключ конфигурации специфичен для
  модели бэкендов аутентификации Airflow 2.x; документация Airflow 3.x (в версии "stable" на момент
  написания этой проверки) больше его не упоминает, перейдя на другую модель аутентификации API на
  основе auth-manager — эту проверку, возможно, потребуется пересмотреть, когда будет подтверждён
  (если вообще существует) эквивалент в Airflow 3.x.

Исследовано и отклонено, с указанием фактической меры по снижению риска:
- `AIRFLOW__CORE__FERNET_KEY`/`AIRFLOW__API__SECRET_KEY` как переменные окружения в открытом виде —
  проверено по отрендеренному выводу Deployment чарта: обе всегда передаются через `secretKeyRef`,
  никогда не встраиваются напрямую. **Уже смягчено** (сам чарт не предоставляет небезопасного
  пути); если значение когда-нибудь будет встроено каким-то другим способом, это должны поймать
  общие проверки секретов этого инструмента, а не отдельная проверка Airflow.
- Предупреждение о "статическом/стандартном секретном ключе веб-сервера", которое чарт выводит как
  UI-алерт — скрыто за проверкой версии чарта (`airflowVersion < 3.0.0`), которая никогда не
  срабатывает на текущей стандартной установке (`3.2.2`), а само сгенерированное значение —
  случайность, сгенерированная Helm-шаблоном для каждой установки, а не фиксированное известное
  значение по умолчанию, как `admin_key` у APISIX. Слишком узко по версии и не проверяемое
  фиксированное значение.

## Apache APISIX (CRD `apisix.apache.org/v2` + проверки содержимого ConfigMap)

- `apisix.admin-api-default-key` (Critical) — отрендеренный `config.yaml` (ключ данных ConfigMap)
  всё ещё содержит один из буквальных ключей Admin API по умолчанию, которые официальный Helm-чарт
  `apisix/apisix` поставляет в собственном `values.yaml` (`admin: edd1c9f034335f136f87ad84b625c8f1`,
  `viewer: 4054f7cf07e344346cd3f287985e76a2`) — собственный встроенный комментарий чарта рядом с
  этим полем: "Настоятельно рекомендуется изменить это значение для защиты Admin API APISIX.
  Отключение этого параметра конфигурации означает, что Admin API не требует никакой
  аутентификации." Оставленный ключ по умолчанию предоставляет полный контроль над control-plane
  (маршруты, upstream'ы, consumer'ы) любому, кто может достучаться до порта Admin API. Намеренно
  узкая проверка: только точные буквальные значения по умолчанию, до сих пор присутствующие в
  чарте сегодня, а не общая эвристика "слабый ключ", которую этот инструмент не может оценить.
- `apisix.admin-auth-disabled` (Critical) — `config.yaml` устанавливает
  `admin_key_required: false`. Официальная сырая конфигурация
  ([config.yaml.example](https://github.com/apache/apisix/blob/master/conf/config.yaml.example)):
  `` admin_key_required: true   # Enable Admin API authentication by default for security. ``
  ("включить аутентификацию Admin API по умолчанию для безопасности") — установка в `false`
  полностью отключает аутентификацию Admin API, независимо от того, какой `admin_key` настроен. Не
  рендерится собственным `values.yaml` Helm-чарта (полагается на внутреннее значение APISIX по
  умолчанию, равное `true`), поэтому срабатывает только если пользователь переопределяет сырое
  содержимое конфигурации напрямую — в этом случае ситуация серьёзнее, чем слабый/стандартный ключ.
- `apisix.admin-allow-wide-open` (High) — `allow_admin` в `config.yaml` включает `0.0.0.0/0` (или
  `::/0`). Тот же источник: "Ограничить доступ к Admin API по IP-адресам. ... Если не задано,
  разрешён любой IP-адрес." Сам официальный Helm-чарт по умолчанию задаёт здесь `127.0.0.1/24`
  (проверено по отрендеренному выводу чарта), так что запись `0.0.0.0/0` — это явное расширение,
  которого стандартная установка никогда не производит — защита на дополнительном уровне,
  независимая от двух проверок выше: даже сильный, ротируемый ключ с обязательной аутентификацией
  достижим откуда угодно без этой настройки.
- `apisix.etcd-connection-plaintext` (Medium) — записи `etcd.host` в `config.yaml` используют
  `http://` вместо `https://`. Источник слабее, чем у двух проверок выше: собственный
  [пример конфигурации](https://apisix.apache.org/docs/apisix/deployment-modes/) APISIX и
  официальный Helm-чарт `apisix/apisix` оба по умолчанию используют `http://` для "традиционного"
  режима (проверено по отрендеренному выводу чарта) — только пример документации для "раздельного"
  режима использует `https://`, без явного императивного предупреждения от самой APISIX. Аргумент
  в пользу серьёзности вместо этого опирается на документацию самого etcd: "Кластер etcd, который
  не включает функции безопасности, может раскрыть свои данные любым клиентам" — etcd — это место,
  где APISIX хранит *всю* конфигурацию маршрутизации/плагинов/consumer'ов, достижимое без
  прохождения через собственную аутентификацию Admin API вообще, если сам etcd доступен извне. Тот
  же паттерн межпроектного обоснования, что и у `istio.gateway-weak-tls-version` (которая ссылается
  на IETF RFC 8996, а не на предупреждение, написанное самой Istio).
- `apisix.tls-weak-protocol-enabled` (High) — `apisix.ssl.ssl_protocols` в `config.yaml` включает
  `TLSv1`, `TLSv1.1` или `SSLv3`. Собственная
  [документация по протоколам SSL](https://apisix.apache.org/docs/apisix/ssl-protocol/) APISIX:
  значение по умолчанию — `"TLSv1.2 TLSv1.3"`, и "по соображениям безопасности набор шифрования,
  используемый по умолчанию в APISIX, не поддерживает TLSv1.1 и более ранние версии" — их поддержка
  является намеренным отходом от этого значения по умолчанию. Сопоставление с учётом границ слов,
  чтобы простое `TLSv1` не давало ложное срабатывание на подстроках `TLSv1.2`/`TLSv1.3` в (очень
  распространённом) неизменённом значении по умолчанию.
- `apisix.tls-skip-mtls-uri-regex-wildcard` (High) — `spec.client.skip_mtls_uri_regex` CRD
  `ApisixTls` содержит шаблон, совпадающий со всем (`.*`, `/.*`, `.+`, `^.*$`, `^/.*$`). Проверено
  напрямую по CRD apisix-ingress-controller
  (`config/crd/bases/apisix.apache.org_apisixtlses.yaml`, `apisix.apache.org/v2`, множественное
  число `apisixtlses`): поле "содержит регулярные выражения URI для пропуска проверки взаимного
  TLS." Тот же паттерн "отслеживать конкретное опасное значение, а не просто наличие поля", что и у
  `victoriametrics.vmauth-unauthorized-access-wildcard-path` — само поле является законным,
  документированным механизмом списка разрешений (например, для пути `/healthz`); только значение
  wildcard полностью сводит на нет mTLS.

Также исследовано и отклонено: наличие/отсутствие `ApisixTls.spec.client.caSecret` — не найдено
документированной формы небезопасного значения, помимо случая с wildcard-регулярным выражением
выше (настроен mTLS или нет — это решение о развёртывании, а не само по себе понижение защиты).
Маршрут, явно удаляющий ранее требовавшийся плагин аутентификации (`ApisixRoute`/
`ApisixPluginConfig`) — это вопрос сравнения с базовым состоянием/диффа ("был ли этот маршрут
защищён раньше?"), который проверка на основе одного объекта структурно не может выразить;
известный пробел, нет существующей меры по снижению риска.

Также исследовано: собственный встроенный RBAC etcd (пользователи/роли по префиксу ключа,
настраиваемые через `etcdctl`) — реальная функция etcd, но она полностью настраивается на стороне
сервера etcd — ничто в собственном `config.yaml` APISIX не отражает и не задаёт её (поля на стороне
клиента — это просто `host`/`user`/`password`/`tls`), поэтому нет объекта APISIX, который этот
инструмент мог бы для этого проверить. Незаданные `etcd.user`/`etcd.password` тоже не проверяются:
отсутствие однозначно не означает "нет аутентификации", поскольку многие законные развёртывания
полагаются на сетевую изоляцию (приватный etcd, недоступный извне кластера) вместо учётных данных
на уровне etcd — тот же класс ситуативного поля, что и `sslmode` PgBouncer у CNPG выше, не единое
документированное правильное/неправильное значение.

## Calico (`crd.projectcalico.org`)

- `calico.felixconfiguration-wireguard-disabled` (Medium) —
  `FelixConfiguration.spec.wireguardEnabled` не равен `true`. Собственная
  [документация по шифрованию WireGuard](https://docs.tigera.io/calico/latest/network-policy/encrypt-cluster-pod-traffic)
  Calico: "Включите WireGuard для защиты трафика подов внутри кластера при передаче по сети в
  кластере Calico." По умолчанию `false` — проверено напрямую по собственному исходному коду Felix
  (`felix/config/config_params.go`: `` WireguardEnabled bool `config:"bool;false"` ``). В
  dual-stack кластерах также следует установить `wireguardEnabledV6` (отдельно не проверяется).
  `FelixConfiguration` — это кластерный синглтон (по соглашению называемый `default`), поэтому эта
  проверка отвечает на вопрос "включено ли шифрование на уровне всего кластера", а не для каждого
  workload'а отдельно.
- `calico.felixconfiguration-default-endpoint-to-host-action-permissive` (Medium) —
  `spec.defaultEndpointToHostAction` равен `Accept` или `Return` (без учёта регистра, согласно
  собственному шаблону валидации CRD Felix). Проверено напрямую по собственному исходному коду
  Felix (`felixconfig.go`, комментарий к полю `DefaultEndpointToHostAction`): "По умолчанию Calico
  блокирует трафик от endpoint'ов workload'ов к самому хосту действием iptables 'DROP'... Используйте
  ACCEPT, чтобы безусловно принимать пакеты от workload'ов после обработки, или RETURN, чтобы
  принимать пакеты от workload'ов, проходящие без изменений." Medium, а не High: радиус поражения
  ограничен трафиком workload→хост, а не workload↔workload.
- `calico.felixconfiguration-allow-ipip-packets-from-workloads` (High) и
  `calico.felixconfiguration-allow-vxlan-packets-from-workloads` (High) —
  `spec.allowIPIPPacketsFromWorkloads`/`spec.allowVXLANPacketsFromWorkloads` равно `true` (оба по
  умолчанию `false`). Проверено напрямую по собственному исходному коду Felix (`felixconfig.go`):
  каждое поле "управляет тем, будет ли Felix добавлять правило, отбрасывающее IPIP/VXLAN
  инкапсулированный трафик от workload'ов." Включение любого из них — известная техника, с помощью
  которой workload может протащить трафик мимо принуждения NetworkPolicy, которое проверяет только
  внутренний, деинкапсулированный пакет — явный, общекластерный отказ от этой защиты.

Также исследовано и отклонено: `prometheusMetricsEnabled` — за отведённое время не найдено явного
предупреждения "раскрывает метрики без аутентификации" в собственной документации Calico; отклонено
из-за недостаточной обоснованности источником, а не потому, что это признано безопасным.
`policySyncPathPrefix` (сокет синхронизации политик Dikastes/Envoy, нужный для интеграции
Istio+Calico) — флаг включения функции, выключенной по умолчанию, сам по себе не ослабляет
существующее значение по умолчанию. Проблемы с действием `Pass`/порядком правил в
`GlobalNetworkPolicy`/`NetworkPolicy` (собственных CRD Calico) — реальный, документированный класс
неправильной конфигурации, но это взаимодействие между правилами/политиками с порядком, без единого
плохого значения на одном объекте; известный пробел, нет существующей меры по снижению риска.

Не проверяется: покрытие default-deny в `NetworkPolicy`/`GlobalNetworkPolicy`. Собственная
документация Calico описывает только *неявное* поведение default-deny в конце уровня (tier), а не
паттерн "ваш объект политики должен выглядеть как X", проверяемый на одном объекте — действительно
ли default-deny действует для данного workload'а — это вопрос покрытия, уже решаемый в общем виде
(на основе присутствия Cilium/Calico) проверкой `netpol-analyzer.no-network-policy-coverage`.

## KubeVirt (`kubevirt.io`)

- `kubevirt.kubevirt-use-emulation-enabled` (Medium) — у общекластерного объекта конфигурации
  `KubeVirt` поле `spec.configuration.developerConfiguration.useEmulation` равно `true`.
  Собственный комментарий в исходном коде KubeVirt
  (`staging/src/kubevirt.io/api/core/v1/types.go`): "UseEmulation можно установить в true, чтобы
  разрешить переход к программной эмуляции", когда аппаратная виртуализация недоступна — и его
  [документация по программной эмуляции](https://kubevirt.io/user-guide/operations/software_emulation/),
  на которую ссылается официальное руководство по установке: "Если `useEmulation` включено, `qemu`
  будет использоваться для программной эмуляции в случае, если аппаратная эмуляция через `/dev/kvm`
  недоступна." Источник слабее, чем у большинства проверок здесь (нет явного предупреждения о
  безопасности от самой KubeVirt, тот же уровень, что и `istio.gateway-weak-tls-version`) —
  программная эмуляция (QEMU TCG) лишена аппаратно обеспечиваемой изоляции VT-x/AMD-V, которую даёт
  `/dev/kvm`, что создаёт существенно большую поверхность для побега из виртуальной машины; поле
  также находится в `developerConfiguration` — собственном соглашении KubeVirt об именовании
  настроек только для разработки/тестирования.
- `kubevirt.host-disk-volume` (High) — у `VirtualMachine`/`VirtualMachineInstance` есть том с
  установленным `hostDisk`. Собственное
  [руководство пользователя](https://kubevirt.io/user-guide/storage/disks_and_volumes/) KubeVirt:
  "Тип тома `hostDisk` предоставляет возможность создать или использовать образ диска,
  расположенный где-то на узле. Он работает аналогично `hostPath` в Kubernetes" — та же проблема
  доступа к файловой системе узла, которую для обычных Pod'ов отслеживает `workload.no-hostpath-volumes`
  этого инструмента, но на специфичной для KubeVirt форме поля, которую та проверка не охватывает.
  Одно выражение покрывает и `VirtualMachine` (`spec.template.spec.volumes[]`), и голый
  `VirtualMachineInstance` (`spec.volumes[]` напрямую) — проверено по реальному исходному коду Go,
  а не предположено.
- `kubevirt.root-feature-gate-enabled` (Critical) — массив `featureGates` в CR `KubeVirt` в поле
  `spec.configuration.developerConfiguration.featureGates` включает `"Root"`. Проверено напрямую по
  собственному исходному коду KubeVirt
  (`pkg/virt-api/webhooks/mutating-webhook/mutators/vmi-mutator.go`): `if !clusterConfig.RootEnabled()
  { markAsNonroot(newVMI) }` — каждая VMI модифицируется в момент admission, чтобы запускать
  virt-launcher от non-root (UID 107), *если* этот gate не включён, в случае включения эта
  модификация пропускается, и virt-launcher запускается от root. `NonRoot` имеет статус General
  Availability (`pkg/virt-config/featuregate/inactive.go` — всегда включён); `Root` остаётся Alpha
  (`.../featuregate/active.go`) — явный, общекластерный отказ от собственной политики безопасности
  по умолчанию KubeVirt, именно та форма "оператор может явно что-то отключить", для которой
  предназначен этот раздел.
- `kubevirt.sidecar-feature-gate-enabled` (High) — тот же массив `featureGates` включает
  `"Sidecar"`. Собственная документация KubeVirt по hook-сайдкарам (`cmd/sidecars/README.md`)
  прямо говорит: "Feature gate Sidecar должен быть включён в Custom Resource KubeVirt перед
  использованием сайдкаров" и "После включения любой владелец ВМ может использовать его для запуска
  произвольного кода в контексте virt-launcher, что может иметь непредвиденные последствия" —
  собственное признание первой стороны, что этот gate является общекластерным opt-in для выполнения
  произвольного кода.
- `kubevirt.hook-sidecar-annotation-present` (High) — у `VirtualMachine`/`VirtualMachineInstance`
  установлена аннотация `hooks.kubevirt.io/hookSidecars` (проверяется и в `metadata.annotations`, и,
  для `VirtualMachine`, в `spec.template.metadata.annotations` — согласно собственной документации
  KubeVirt, в VMI фактически распространяется только последняя). Дополняет проверку gate'а выше:
  отслеживает фактическое использование механизма выполнения произвольного кода на уровне отдельной
  ВМ, а не только включение на уровне кластера.
- `kubevirt.containerpath-volume-exposes-sa-token` (High) — поле `path` тома `containerPath` у ВМ
  начинается с `/var/run/secrets/kubernetes.io/serviceaccount`. Собственная документация KubeVirt
  (`docs/storage/containerpath_volumes.md`, раздел "Соображения безопасности"): "ВМ получают доступ
  к любым файлам в пределах указанного пути контейнера — открывайте доступ только к путям,
  содержащим данные, предназначенные для использования внутри ВМ." Документированное,
  предполагаемое использование этой функции — предоставление доступа к токену внешней облачной
  идентичности, созданному специально для этой цели (AWS IRSA, Azure workload identity, ...); эта
  проверка отслеживает только собственный путь к токену Kubernetes API пода по умолчанию, а не
  использование `containerPath` в целом — легитимный путь в стиле IRSA (проверенная тестовая
  конфигурация: `.../eks.amazonaws.com/serviceaccount`) её не срабатывает.

Также исследовано в рамках этого прохода и отклонено с указанием причины (по тому же критерию
"понять почему и отметить меру по снижению риска", что и для любого другого отказа в этом
документе):
- `spec.domain.devices.hostDevices[]`/`gpus[]` на уровне VM/VMI (*запрос* устройства с passthrough)
  — действительно ли конкретное запрашиваемое имя устройства опасно, полностью зависит от отдельного
  списка разрешений `permittedHostDevices` в CR `KubeVirt` — межобъектная корреляция, которую
  проверка на одном объекте VAP выполнить не может. Для этого конкретного пробела нет существующей
  меры по снижению риска; отмечено как известное ограничение, тот же класс, что и межобъектный
  пробел между RBAC-биндингом и ролью, отмеченный ниже.
- Feature gates `GPU`/`HostDevices`/`ConfigurableHypervisor` — в отличие от `Root`/`Sidecar`, ни
  один не несёт явного предупреждения о безопасности, написанного авторами KubeVirt (собственный
  комментарий в исходном коде `ConfigurableHypervisor` говорит только "разрешает использование
  гипервизоров, отличных от KVM"). Их отслеживание означало бы угадывание серьёзности без
  документированной основы — отклонено по критерию обоснованности источником, а не по соображениям
  безопасности.
- Методы сетевого связывания `bridge`/`masquerade` (документированно требуют дополнительных
  capabilities пода по сравнению с `passt`) — отклонено как проверка: `masquerade` — это *стандартный*
  метод связывания основной сети у KubeVirt для подавляющего большинства обычных ВМ, поэтому его
  отслеживание было бы почти чистым шумом, в отличие от `hostDisk`, где PVC — обычная,
  непримечательная альтернатива. Нет существующей меры по снижению риска; известный пробел, только
  если желательна видимость сетевых capability по каждой ВМ отдельно.
- `macspoofchk`/`spoofchk` — фактическая настройка находится на объекте
  `NetworkAttachmentDefinition`, на который есть ссылка, а не в собственной спецификации VM/VMI:
  межобъектная зависимость, непроверяемая по одному объекту.
- Feature gate `DisableCustomSELinuxPolicy` — функционально неактуален: подтверждено через
  `kubevirt/kubevirt#11266` (влит 2025-01-21, "Полностью удалить неиспользуемую пользовательскую
  политику SELinux"), что политика, которую когда-то контролировал этот gate, больше ничем не
  используется; константа gate'а остаётся только для обратной совместимости.
- `permittedHostDevices` (собственный список разрешений CR `KubeVirt`) — повторно подтверждённый
  отказ с первого прохода: документация KubeVirt описывает его исключительно как предполагаемый
  механизм администраторского разрешения, без базового уровня "должен быть пустым".
- `accessCredentials` (внедрение SSH-ключа/пароля) — повторно проверено напрямую по
  `staging/src/kubevirt.io/api/core/v1/schema.go`: и `SSHPublicKeyAccessCredential`, и
  `UserPasswordAccessCredential` остаются только на основе `SecretRef`; поля с открытым текстом
  учётных данных в текущей схеме не существует.
- Feature gates `Passt`/`Macvtap`/`PasstIPStackMigration`/`ExperimentalVirtiofsSupport` — все
  отмечены в исходном коде как `State: Discontinued` (например, "Сетевое связывание Macvtap
  прекращено начиная с v1.3") — нефункциональны, даже если присутствуют в манифесте, отслеживать не
  стоит.
- Поля прошивки/загрузчика/secure boot и `autoattachGraphicsDevice`/поля, связанные с VNC — не
  найдено документированной формы небезопасного значения ни в документации KubeVirt, ни в
  комментариях исходного кода; отклонено согласно критерию обоснованности источником этого
  репозитория, а не путём угадывания серьёзности.
- Стандартные ClusterRole `kubevirt.io:admin`/`:edit`/`:view` и доступ к консоли/VNC — реальный риск
  в том, *кто привязан* к этим ролям — это межобъектный вопрос RBAC. **Уже смягчено**: проверки
  `rbac-analyzer.*` этого репозитория уже в общем виде покрывают широкие/рискованные предоставления
  ClusterRoleBinding, независимо от того, к какой ClusterRole они относятся.

Пока не охвачено, отмечено как известный пробел (как и `calico-node` выше): `virt-handler`, агент
уровня узла, который фактически запускает ВМ и которому нужен `/dev/kvm` (и, вероятно, другой
доступ уровня хоста), архитектурно относится к типу System так же, как агенты Cilium/Falco — но он
создаётся динамически `virt-operator` на основе CR `KubeVirt`, а не поставляется в статическом
манифесте установки, поэтому его реальные требования к привилегиям пока не были проверены на живом
кластере. Продвижение его во встроенное исключение требует сначала этой проверки, а не
предположения. Запись инвентаризации компонентов `KubeVirt` (категория Application) охватывает
только `virt-operator`, общекластерный control-plane Deployment — проверено по официальному
релизному манифесту (метка `kubevirt.io: virt-operator`).

## Temporal (CRD `temporal.io/v1beta1` + проверки ConfigMap/Deployment)

Проверки CRD ниже нацелены на `TemporalCluster` из community-оператора
[alexandrevilain/temporal-operator](https://temporal-operator.pages.dev/) — сам Temporal не
поставляет собственный CRD; гораздо более распространённый путь — официальный чарт
`temporalio/helm-charts`, который вместо этого покрывается проверками ConfigMap/Deployment.

- `temporal.authorization-not-configured` (Critical) — отрендеренный `config_template.yaml` (ключ
  данных ConfigMap, не фиксированное имя объекта — чарт называет его `{{ temporal.fullname }}-config`,
  что варьируется от релиза к релизу) не содержит блока `authorization:` внутри `global:`.
  Собственная [документация по безопасности](https://docs.temporal.io/self-hosted-guide/security)
  Temporal: "Если вы явно не настроили Authorizer, Temporal использует `noopAuthorizer` по
  умолчанию. Это значение по умолчанию разрешает каждый API-запрос, без аутентификации или контроля
  доступа" — и прямо: "ваше развёртывание фактически открыто для любого, у кого есть сетевой
  доступ." Проверено по собственному шаблону чарта: весь блок рендерится только если пользователь
  задаёт `server.config.authorization`, а собственный `values.yaml` чарта поставляет его полностью
  закомментированным.
- `temporal.operator-authorizer-empty` (Critical) — `TemporalCluster.spec.authorization.authorizer`
  не задан или равен `""`. Тот же лежащий в основе риск, что и у проверки выше, для кластеров,
  управляемых оператором. Проверено напрямую по собственной схеме CRD оператора: "может быть
  оставлено пустой строкой, чтобы использовать noop-авторизатор (noopAuthorizer)."
- `temporal.internode-tls-disabled` (High) и `temporal.frontend-tls-disabled` (High) — в том же
  ConfigMap `global.tls.internode.enabled`/`global.tls.frontend.enabled` равно `false`. Проверено
  по собственному `values.yaml` чарта: оба по умолчанию `false`. Документация Temporal описывает
  mTLS как документированный способ защиты трафика между серверами и клиентского трафика; открытый
  вариант без шифрования явно описан как осознанный выбор оператора ("запускать незащищённые
  инстансы внутри среды VPC"), а не как рекомендуемое значение по умолчанию.
- `temporal.web-auth-not-enabled` (High) — `Deployment` на `apps/v1`, запускающий образ
  `temporalio/ui*`, не имеет переменной окружения `TEMPORAL_AUTH_ENABLED=true`. Собственная
  документация Temporal по интеграции SSO для Web UI утверждает, что для её включения "необходимо...
  установить `TEMPORAL_AUTH_ENABLED=true`" — то есть по умолчанию аутентификация отключена.
  Широкое сопоставление (любой Deployment) + узкое условие (точный префикс образа) — тот же
  паттерн, что и у `kyverno.admission-controller-force-failure-policy-ignore`.

Исследовано и отклонено: стандартные пароли бэкенд-хранилища БД/Cassandra/Elasticsearch —
собственный `values.yaml` чарта нигде не содержит жёстко заданного значения по умолчанию; каждое
учётное данное бэкенд-хранилища передаётся через ссылки `existingSecret`/`secretKey`, поэтому нет
известного значения по умолчанию для проверки даже с `--read-secret-values`. Обход
`useExternalFrontend: false` у admin-tools — документированный, предполагаемый паттерн
административного доступа, а не неправильная конфигурация; фактический риск (кто может достучаться
до пода admintools) — это вопрос NetworkPolicy/RBAC, уже покрываемый общими проверками
`network.*`/`rbac-analyzer.*` этого репозитория. На момент написания нет опубликованных GitHub
Security Advisories для `temporalio/temporal` или `temporalio/ui`, поэтому, в отличие от проверки
Redis у ArgoCD, здесь нет CVE-конкретной сигнатуры, к которой можно было бы привязать проверку.

## Grafana Loki (CRD `loki.grafana.com/v1` `LokiStack` + проверки ConfigMap)

- `loki.auth-disabled` (High) — отрендеренный `loki.yaml` (ключ данных ConfigMap) устанавливает
  `auth_enabled: false`. Собственный справочник конфигурации Loki: "Включает аутентификацию через
  заголовок `X-Scope-OrgID`, который должен присутствовать, если значение true. Если false, OrgID
  всегда будет установлен в 'fake'." Проверено по собственному `values.yaml` официального чарта
  `grafana/loki`: `auth_enabled: true` — собственное значение чарта по умолчанию — `false`
  появляется только если оператор явно его переопределил. Оговорка, актуальная даже при `true`:
  собственная документация Loki утверждает: "Grafana Loki не поставляется со встроенным уровнем
  аутентификации. Вы должны запускать аутентифицирующий обратный прокси перед своими сервисами" —
  этот флаг только обеспечивает разделение по идентификатору тенанта между вызывающими сторонами,
  уже прошедшими этот прокси, сам по себе он не является аутентификацией; текст рекомендации
  явно это указывает, чтобы избежать чрезмерного доверия к успешно прошедшему скану.
- `loki.lokistack-tenants-not-configured` (Medium) — у CRD `LokiStack` (Loki Operator, в основном
  установки OpenShift) не задан `spec.tenants`. Проверено напрямую по собственному исходному коду
  оператора на Go: "Tenants определяет спецификацию аутентификации и авторизации по тенантам для
  компонента lokistack-gateway" — это единственная точка конфигурации аутентификации/авторизации
  всего оператора. Medium, а не High: этот репозиторий независимо не подтвердил точное поведение
  оператора (какой шлюз, если вообще какой-либо, разворачивается), когда это поле не задано.

## Grafana Tempo (проверки ConfigMap)

- `tempo.receiver-tls-not-configured` (Medium) — у отрендеренного `tempo.yaml` настроен приёмник
  `otlp:` без блока `tls:` где-либо в файле. Источник слабее, чем у большинства проверок здесь
  (документация Tempo описывает пути настройки TLS, но не предупреждает отдельно, что их пропуск
  небезопасен — тот же уровень, что и `istio.gateway-weak-tls-version`). Намеренно грубая проверка:
  надёжно определить область действия "блок `tls:` является прямым дочерним элементом именно этого
  приёмника" через регулярное выражение по текстовому блобу YAML недостаточно надёжно, чтобы
  поставлять без реального риска ложных срабатываний/пропусков, поэтому эта проверка только
  отслеживает "присутствует ли слово `tls:` вообще где-либо в файле" при наличии приёмника OTLP —
  обмен точности на проверку, которая не сработает ошибочно, ценой возможного ложного прохождения,
  если `tls:` появляется где-то ещё, не относящемся к приёмнику.

Исследовано и отклонено: `multitenancy_enabled: false` — в отличие от `auth_enabled` у Loki,
собственное значение чарта Tempo по умолчанию тоже `false` (проверено по
`charts/tempo-distributed/values.yaml`), так что его отслеживание срабатывало бы на подавляющем
большинстве неизменённых установок — это не понижение защиты, инициированное оператором, паттерн,
на который был нацелен конкретно этот проход. Собственная модель аутентификации Tempo (нет
встроенного уровня аутентификации, как и у Loki) не имеет поля, видимого на уровне admission, для
проверки — фактическая мера по снижению риска (аутентифицирующий обратный прокси) — это
межобъектный вопрос, зависящий от внешнего инструмента, который модель CEL этого инструмента на
основе одного объекта структурно не может проверить; известный пробел, нет существующей меры по
снижению риска.

## Apache Superset (проверки Secret/Deployment — без CRD)

- `superset.secret-key-default-value` (Critical, **требует `--read-secret-values`**, см.
  [Режим секретов](./secrets-mode.md)) — значение `SUPERSET_SECRET_KEY` в `Secret` равно base64-форме
  собственного хорошо известного примера значения Superset. Проверено напрямую по исходному коду
  Superset: `superset/constants.py` определяет `CHANGE_ME_SECRET_KEY =
  "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"`, а `superset/config.py` использует это значение по
  умолчанию, если `SUPERSET_SECRET_KEY` не задан. Это **CVE-2023-27524** — известный/стандартный
  `SECRET_KEY` позволяет атакующему подделать cookie сессии, обойти аутентификацию и получить
  доступ к SQL Lab (RCE в некоторых конфигурациях). Собственный `values.yaml` официального чарта
  показывает эту точную строку в качестве примера документации для
  `extraSecretEnv.SUPERSET_SECRET_KEY` — реальная, правдоподобная ловушка copy-paste. Проверяемо
  вообще только потому, что чарт рендерит записи `extraSecretEnv` как отдельные ключи данных
  Secret, а не потому, что этот инструмент может заглянуть внутрь (непрозрачного, base64,
  неразбираемого этим движком) целого блоба `superset_config.py`, который чарт тоже рендерит в
  Secret — см. ниже.
- `superset.talisman-disabled` (Medium) — у контейнера Superset `TALISMAN_ENABLED` установлен в
  ложное значение. Проверено напрямую по собственному исходному коду Superset: `TALISMAN_ENABLED =
  cast_to_boolean(os.environ.get("TALISMAN_ENABLED", True))` — прямое переопределение через
  переменную окружения, по умолчанию `true`. Talisman — это middleware Flask-Talisman Superset
  (CSP, HSTS, X-Frame-Options и аналогичные заголовки ответа, связанные с безопасностью). Уровень
  со слабым источником (тот же, что и у `istio.gateway-weak-tls-version`).

Исследовано и отклонено: `AUTH_TYPE`/`AUTH_ROLE_PUBLIC`/`PUBLIC_ROLE_LIKE`/`WTF_CSRF_ENABLED`/
`PREVENT_UNSAFE_DB_CONNECTIONS`/`FEATURE_FLAGS` — все реальные, все подтверждены в собственном
`config.py` Superset, но официальный Helm-чарт рендерит *весь* `superset_config.py` Superset в
**Secret** (`templates/secret-superset-config.yaml`), а не в ConfigMap, как `webserver_config.py` у
Airflow. Этот движок намеренно никогда не декодирует base64 значения Secret (см.
[Режим секретов](./secrets-mode.md)), поэтому проверка подстроки/регулярного выражения по
непрозрачному base64-блобу невозможна — внутрь него никак нельзя заглянуть, проверяемо это или нет.
Известный, структурный пробел; нигде не смягчён. `GUEST_TOKEN_JWT_SECRET`/
`GLOBAL_ASYNC_QUERIES_JWT_SECRET` также по умолчанию равны известным примерным значениям
(`test-guest-secret-change-me`, `test-secret-change-me`) в `superset/constants.py`, из того же
семейства CVE-2023-27524 — но оба являются обычными присваиваниями внутри самого
`superset_config.py`, не обёрнутыми в `os.environ.get()`, как `SECRET_KEY`, поэтому нет
раскрытой переменной окружения/ключа Secret для проверки тоже. Тот же пробел, что и выше.

## Metabase (проверки переменных окружения Deployment — без CRD, без официального Helm-чарта)

Metabase вообще не поставляет официальный Helm-чарт (у каждого community-чарта своё соглашение о
метках — метка обнаружения `app: metabase` в `internal/thirdparty/components.yaml` соответственно
менее надёжна, чем любая другая запись в этом файле, проверена только по самому часто используемому
community-чарту, а не по официальному). Вся конфигурация — через обычные переменные окружения
контейнера (`MB_*`), что делает её более проверяемой, чем непрозрачный блоб Secret у Superset, а не
менее.

- `metabase.public-sharing-enabled` (Medium) — у контейнера `metabase/metabase*` нет переменной
  окружения `MB_ENABLE_PUBLIC_SHARING=false`. Собственный справочник переменных окружения Metabase:
  "Разрешить администраторам создавать публично доступные ссылки (и встраиваемые iframe) для
  Questions и Dashboards?" **По умолчанию: true.** После того как администратор создаёт публичную
  ссылку, любой, у кого есть URL, видит эти данные без какой-либо аутентификации — реальная,
  документированная, неаутентифицированная по замыслу поверхность раскрытия, оставленная во
  включённом по умолчанию состоянии.
- `metabase.encryption-secret-key-missing` (Medium, источник слабее) — у контейнера
  `metabase/metabase*` нет переменной окружения `MB_ENCRYPTION_SECRET_KEY` (проверяется только
  наличие имени переменной, а не её значение — выполняется независимо от того, задана ли она
  напрямую или через `secretKeyRef`, поэтому режим секретов не нужен). Источник слабее, чем у
  большинства проверок здесь: собственная документация Metabase о шифровании данных в покое
  использует слово "может", а не императивное "должен"/"всегда" — документированная возможность, а
  не документированное требование (тот же уровень, что и `istio.gateway-weak-tls-version`).
  Фактический риск при отсутствии: каждая строка подключения к базе данных/пароль, которыми
  управляет Metabase, хранится в открытом виде в собственной базе данных приложения Metabase.

Исследовано и отклонено: `MB_JWT_SHARED_SECRET` — реальная переменная, но по умолчанию не задана,
без конкретного известного небезопасного значения для сравнения, ситуативная (на тех же основаниях,
что и отказ от проверки `sslmode` PgBouncer у CNPG). `MB_MFA_ENFORCEMENT` (по умолчанию `"off"`) —
отсутствие принудительного MFA по умолчанию близко к универсальному для всей этой категории
продуктов, не явное понижение защиты от реальной безопасной базовой линии; отклонено как шум, то же
обоснование, что и отказ от проверки "Audit является значением по умолчанию" у Kyverno.
`MB_API_KEY` (аутентификация эндпоинта вебхука `/notify`) — исследовано, означает ли отсутствие,
что эндпоинт открыт; свидетельства указывают на обратное (отчёты описывают отказ закрытым способом,
ошибку при отсутствии значения, а не пропуск запросов) — отклонено, вместо того чтобы утверждать не
подтверждённую уязвимость. `MB_ENABLE_EMBEDDING_*`/`MB_EMBEDDING_SECRET_KEY` — по умолчанию
`false`/не задано, то есть уже безопасно по умолчанию и только по выбору (opt-in), нет небезопасного
значения по умолчанию для отслеживания.

## Velero — намеренно не охвачен

Исследовано и явно отклонено: собственные рекомендации по безопасности Velero описывают его
фактическую поверхность риска как RBAC в отношении того, кто может создавать объекты
`Backup`/`Restore` (уже покрыто в общем виде проверками `rbac-analyzer.*` этого инструмента) и
политики бакетов объектного хранилища (полностью внешние по отношению к Kubernetes).
`BackupStorageLocation.spec.config` — нетипизированная, специфичная для провайдера
`map[string]string` без согласованного имени поля для чего-то вроде "пропустить проверку TLS" в
S3/GCS/Azure/MinIO — недостаточно твёрдая почва для построения проверки без угадывания.
