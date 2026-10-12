# kubectl-audit — документация

Плагин `kubectl` (`kubectl audit ...`) для аудита состояния безопасности Kubernetes — живого
кластера, статических файлов манифестов, или и того, и другого сразу.

[Быстрый старт](./getting-started.md)

## Что проверяется

- **Проверки-политики** — написаны как настоящие объекты `admissionregistration.k8s.io/v1
  ValidatingAdmissionPolicy` (VAP) с CEL-выражениями. Тот же самый YAML, по которому идёт
  сканирование, можно применить через `kubectl apply -f`, чтобы включить правило в кластере на
  уровне admission. Чтобы добавить проверку, достаточно положить новый файл в директорию политик —
  изменения кода не нужны. См. [Написание политик](./writing-policies.md).
- **RBAC-анализ на наименьшие привилегии** — строит эффективную модель прав для каждого субъекта
  (User/Group/ServiceAccount) по Role, ClusterRole и их биндингам (включая разрешение
  ClusterRole на основе `aggregationRule` даже из сырых статических манифестов), и флагает verbs
  эскалации привилегий, доступ exec/attach, широкий доступ к Secrets, самомодификацию RBAC и
  рискованный automount токена ServiceAccount. См. [RBAC-анализ](./rbac.md).
- **Покрытие NetworkPolicy** — флагает workload'ы без применимой NetworkPolicy. Нативная
  NetworkPolicy Kubernetes сопоставляется точно с labels pod-шаблона каждого workload'а; политики
  Cilium и Calico определяются и используются как сигнал покрытия. См.
  [Покрытие NetworkPolicy](./network-policy.md).
- **Соответствие нескольким фреймворкам** — итоговые таблицы по CIS Kubernetes Benchmark, ФСТЭК и
  NSA/CISA Kubernetes Hardening Guidance, оценённые по одним и тем же находкам и проверяемые вместе
  (`--frameworks cis,fstec,nsa`) со сводной итоговой таблицей и перекрёстными ссылками между
  фреймворками. Разделы вне видимости API явно помечаются "Not Applicable", а не тихо
  пропускаются. См. [Фреймворки соответствия](./compliance.md).

## Вывод

- `findings.json` — машиночитаемые находки, модель ролей RBAC и итоговые таблицы соответствия.
- `report.md` — человекочитаемый отчёт, включая то, какие именно ресурсы привели к провалу каждого
  контроля, отрендеренный из полностью настраиваемого Go-шаблона — см.
  [Шаблоны отчёта](./report-templates.md).
- `--fail-on <severity>` — CI-гейт, завершающийся ненулевым кодом при наличии находок указанной
  серьёзности или выше.

## Быстрый старт

```sh
go install github.com/ivanhahanov/kubectl-audit/cmd/kubectl-audit@latest

# Проверить текущий кластер
kubectl audit scan

# Проверить только статические манифесты, с гейтом для CI
kubectl audit scan -f ./manifests --mode static --fail-on high
```

См. [Быстрый старт](./getting-started.md) для установки и полного списка команд, и
[Конфигурация](./configuration.md) для `audit.yaml`.

## Остальная документация

- [Быстрый старт](./getting-started.md) — установка и полный список команд.
- [Конфигурация (`audit.yaml`)](./configuration.md)
- [Фреймворки соответствия](./compliance.md)
- [RBAC-анализ](./rbac.md)
- [Покрытие NetworkPolicy](./network-policy.md)
- [Триаж и Jira](./triage.md)
- [Шаблоны отчёта](./report-templates.md)
- [kubectl-audit-server](./server.md)
- [Режим работы с Secrets](./secrets-mode.md)
- [Istio](./istio.md)
- [Сторонние операторы](./third-party-operators.md)
- [Экспорт в Kyverno](./kyverno-export.md)
- [Написание политик](./writing-policies.md)
- [Собственные проверки и приватные стандарты](./custom-checks.md)
- [Требуемые права доступа (RBAC для самого инструмента)](./permissions.md)

Эта документация — обычный Markdown без привязки к какому-либо генератору сайта: она одинаково
открывается в файловом браузере GitHub, GitLab, Bitbucket и просто в IDE, без отдельной сборки или
хостинга.
