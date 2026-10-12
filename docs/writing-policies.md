# Написание пользовательских политик

Политики — это обычный YAML `ValidatingAdmissionPolicy`. Метаданные, специфичные для аудита
(серьёзность, категория, текст рекомендации, ссылки на контроли CIS), целиком находятся в
`metadata.annotations` под префиксом `audit.k8s-auditor.io/`, поэтому файл остаётся на 100% валидным
для `kubectl apply -f` как реальная принудительно исполняемая политика в кластере:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: org.require-owner-label
  annotations:
    audit.k8s-auditor.io/severity: low
    audit.k8s-auditor.io/category: org-policy
    audit.k8s-auditor.io/remediation: "Add a team label identifying the owning team."
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "has(object.metadata.labels) && has(object.metadata.labels.team)"
      message: "Workload is missing a 'team' label."
```

Распознаваемые аннотации:

| Аннотация | Назначение |
|---|---|
| `audit.k8s-auditor.io/title` | Человекочитаемый заголовок находки (по умолчанию `metadata.name`). |
| `audit.k8s-auditor.io/severity` | `critical\|high\|medium\|low\|info` (по умолчанию `medium`). |
| `audit.k8s-auditor.io/category` | Произвольная метка группировки (по умолчанию `general`). |
| `audit.k8s-auditor.io/remediation` | Отображается в находке и отчёте. Как исправить подтверждённую проблему. |
| `audit.k8s-auditor.io/verification-steps` | Отображается в находке, отчёте и считывается `kubectl triage`. Конкретные, пронумерованные шаги, позволяющие человеку подтвердить, что эта находка — истинное срабатывание в его конкретном окружении, прежде чем действовать на её основании (например, «проверьте, действительно ли этот Service доступен из интернета») — отличается от `remediation`, которая предполагает, что находка уже подтверждена. Эта аннотация задана у каждой поставляемой политики; полное обоснование и способ использования см. в [Triage](./triage.md). |
| `audit.k8s-auditor.io/cis` | Список ID контролей CIS через запятую, с которыми сопоставлена эта политика. |
| `audit.k8s-auditor.io/kb-title`, `.../kb-description`, `.../kb-remediation`, `.../kb-verification-steps` | Опционально: собственные заголовок/описание уязвимости/рекомендация/шаги проверки вашей организации для этой проверки, предназначенные для тикета — внутренние стандарты, корпоративный стиль или просто более понятная формулировка, чем значение по умолчанию — написанные в том же файле политики вместо того, чтобы дополнительно вести отдельную запись `knowledgeBaseFile`. Это не механизм перевода: `message`/CEL-поле `message:` таким способом никогда не переопределяется. Применяется при создании тикета Jira и отображается идентично в детальном представлении TUI triage (`enter`) — см. [Triage: База знаний](./triage.md). Всё, что оставлено неустановленным, просто использует собственное значение инструмента по умолчанию для этого поля. |

Загрузите её с помощью `kubectl audit scan --policy-dir ./my-policies` или добавьте директорию под
`policies.dirs` в `audit.yaml`. См.
[`examples/custom-policy-example.yaml`](../examples/custom-policy-example.yaml).

## Проверяйте перед тем, как полагаться на это

```sh
kubectl audit policy validate ./my-policies
kubectl audit policy list
```

`policy validate` компилирует CEL для каждой политики в указанных директориях и сообщает обо всех
найденных ошибках (а не только о первой), с именем проблемного файла/политики.

## Работа с разными формами workload-ов

Спецификации контейнеров находятся по разным путям в зависимости от объекта: `spec.containers` для
голого `Pod`, `spec.template.spec.containers` для Deployment/StatefulSet/DaemonSet/ReplicaSet и
`spec.jobTemplate.spec.template.spec.containers` для CronJob. Политика, которая должна применяться ко
всем ним, должна ветвиться по форме объекта, поскольку макрос `has()` в CEL проверяет наличие только
*последнего* селектора в цепочке — каждый промежуточный уровень нуждается в собственной защите
`has()`, иначе выражение завершится ошибкой вместо того, чтобы просто вернуть false:

```
(has(object.spec.containers) ? object.spec.containers
  : (has(object.spec.template) && has(object.spec.template.spec) && has(object.spec.template.spec.containers)) ? object.spec.template.spec.containers
  : (has(object.spec.jobTemplate) && has(object.spec.jobTemplate.spec) && has(object.spec.jobTemplate.spec.template) && has(object.spec.jobTemplate.spec.template.spec) && has(object.spec.jobTemplate.spec.template.spec.containers)) ? object.spec.jobTemplate.spec.template.spec.containers
  : []).all(c, /* your condition on c */)
```

Поставляемые политики в
[`policies/workload`](../policies/workload) и
[`policies/network`](../policies/network) все
используют этот паттерн — скопируйте тот, что ближе всего к вашей задаче.

## Ограничения движка, о которых стоит знать

- **`spec.variables` не поддерживается.** Политики, объявляющие его, не компилируются с понятным
  сообщением об ошибке; вместо вынесения выражения в именованную переменную встройте его inline.
- **CEL-переменная `authorizer` не объявлена.** Этот движок проверяет устойчивое состояние
  кластера/манифеста, а не живые запросы на допуск, поэтому у него нет SubjectAccessReview, на
  который можно опереться. Политики, использующие `authorizer.*`, не компилируются — для проверок,
  зависящих от RBAC, используйте вместо этого [анализатор RBAC](./rbac.md).
- **`operations` в `matchConstraints.resourceRules` не фильтруется.** Каждый загруженный ресурс
  оценивается независимо от объявленных в правиле операций (CREATE/UPDATE/DELETE), поскольку
  инструмент проверяет существующие объекты, а не симулирует один конкретный запрос на допуск.
- **Объекты `ValidatingAdmissionPolicyBinding` не используются.** `matchConstraints` каждой
  загруженной политики применяется напрямую к каждому ресурсу — здесь нет уровня косвенности,
  связанного с проводкой в кластере, который нужно было бы моделировать.

## Проверки RBAC и NetworkPolicy — это не политики VAP

Некоторые проверки действительно невозможно выразить одной политикой CEL для одного объекта —
ответ на вопрос «есть ли у этого субъекта чрезмерно широкие эффективные права» или «есть ли у этого
workload-а какой-либо применимый NetworkPolicy» требует сопоставления нескольких объектов (Role +
Binding + субъект, или Workload + каждый NetworkPolicy в его неймспейсе). Вместо этого они
существуют как нативные Go-анализаторы: см. [Анализ RBAC](./rbac.md) и
[Покрытие NetworkPolicy](./network-policy.md).
