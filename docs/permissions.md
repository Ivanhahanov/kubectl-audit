# Необходимые права доступа

kubectl-audit работает с кластером, который сканирует, только в режиме чтения: он никогда не
создаёт, не обновляет, не патчит и не удаляет ничего. В режиме работы с кластером ему нужны
`get`/`list`/`watch` на те виды ресурсов, которые он запрашивает — и ничего больше.

## Два уровня

- **`examples/rbac/clusterrole-readonly.yaml`** — вариант по умолчанию. Всё, что нужно обычному
  `kubectl audit scan`/`kubectl audit rbac analyze`: встроенные виды ресурсов
  ([`internal/loader/cluster.go`](../internal/loader/cluster.go),
  поле `defaultResources` — Pods, Services, Namespaces, ServiceAccounts, ConfigMaps, ResourceQuotas,
  LimitRanges, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs,
  Roles/ClusterRoles/\*Bindings, NetworkPolicies, Ingresses, Validating-/MutatingWebhookConfigurations),
  плюс CRD каждого стороннего оператора, для которого в этом инструменте есть проверки
  (`optionalResources` — Cilium, Calico, Istio, ArgoCD, Vault Secrets Operator, Fluent Operator,
  VictoriaMetrics Operator, CloudNativePG, Kyverno, APISIX, Capsule, KubeVirt, Strimzi, Temporal,
  Grafana Loki). Выдача правила для группы CRD, которая не установлена на конкретном кластере,
  безвредна — оно просто остаётся неактивным: инструмент определяет, установлена ли группа, через
  API discovery, прежде чем вообще пытаться её запрашивать, а не падает с ошибкой на
  отсутствующей. **Намеренно исключает Secrets.**
- **`examples/rbac/clusterrole-with-secrets.yaml`** — всё то же самое, плюс `get`/`list`/`watch`
  на `secrets`. Нужен только при запуске с `--read-secret-values` — см. [Режим работы с
  секретами](./secrets-mode.md). Применяйте его *вместо* readonly-варианта, а не вместе с ним.

Оба манифеста — обычные `ClusterRole` — `kubectl apply -f examples/rbac/clusterrole-readonly.yaml`.
`examples/rbac/serviceaccount-and-binding.yaml` показывает связку `ServiceAccount` +
`ClusterRoleBinding` для запуска этого инструмента как Job/CronJob внутри кластера; человеку,
запускающему его локально через свой kubeconfig, нужны те же глаголы доступа на собственного
пользователя/группу (либо то, что ваша организация уже использует для доступа на чтение, например
встроенный `ClusterRole` `view` плюс группы CRD сторонних операторов выше, которые `view` не
покрывает).

## Зачем выдавать доступ к CRD операторов, которые могут быть даже не установлены

Собственная логика определения компонентов `kubectl-audit` (см. [Сторонние
операторы](./third-party-operators.md)) уже считает «группа CRD не зарегистрирована» обычным,
ожидаемым случаем для большинства кластеров — это строка лога уровня `debug`, а не предупреждение,
и никак не влияет на сканирование. Разбиение readonly-варианта `ClusterRole` по вендорам (чтобы
выдавать только то, что реально установлено) потребовало бы ручной поддержки для каждого кластера
и незаметно устаревало бы при каждом добавлении в инструмент нового поддерживаемого оператора.
Единый поставляемый манифест проще поддерживать в актуальном состоянии и не имеет существенных
недостатков: правило RBAC, ссылающееся на несуществующий ресурс, ничего не выдаёт.

## Поддержание актуальности

Оба манифеста ведутся вручную, а не генерируются. Если вы расширяете этот инструмент новым
сторонним компонентом (см. [Написание политик](./writing-policies.md)) и ему нужен новый CRD,
получаемый из живого кластера, добавьте ресурс в `optionalResources` файла
`internal/loader/cluster.go` **и** в оба файла `examples/rbac/clusterrole-*.yaml` —
`TestClusterRoleManifestsCoverKnownResources` из `internal/loader/clusterrole_test.go` ломает
сборку, если хотя бы один манифест расходится с тем, что загрузчик реально умеет запрашивать,
так что это не может незаметно устареть.
