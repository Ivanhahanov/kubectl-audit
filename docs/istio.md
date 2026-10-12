# Проверки Istio (альфа)

**Альфа**: новее и менее проверено в бою, чем остальные проверки этого инструмента. Заголовок каждой
находки `istio.*` начинается с `[ALPHA]`, и любое сканирование, загружающее объект PeerAuthentication,
AuthorizationPolicy, DestinationRule или Gateway, получает отдельную оговорку в разделе **Scope**
отчёта (не смешивается с «Not covered by this scan» — эти проверки действительно выполняются, просто с
предупреждением о пониженной уверенности, которое стоит прочитать, прежде чем доверять результату).
Относитесь к находкам `istio.*` как к отправной точке для ручной проверки, а не как к окончательному
вердикту.

Девять из них — проверки `ValidatingAdmissionPolicy` для одного объекта
([`policies/thirdparty/istio`](../policies/thirdparty/istio))
— без вычисления эффективной политики между объектами (это делает `istioctl x authz check` на основе
конфигурации Envoy живого сайдкара, что этот статический/основанный на API инструмент структурно не
может воспроизвести). Отдельно от них есть ещё один, десятый, Istio-специфичный нативный Go-анализатор
(`istio-analyzer.no-authorization-policy-coverage`) — он как раз выполняет то самое межобъектное
сопоставление, которое VAP-политикам недоступно; см. [ниже](#istio-analyzerno-authorization-policy-coverage-нативный-анализатор).

В режиме кластера объекты получаются путём разрешения реально обслуживаемой/предпочитаемой версии
`security.istio.io` и `networking.istio.io` через собственный механизм обнаружения API кластера — а не
через версию, захардкоженную в этом инструменте, — поэтому это работает независимо от того, отдаёт ли
кластер `v1` или более старую `v1beta1`, а кластер вообще без установленного Istio молча пропускается,
а не выдаёт ошибку. `matchConstraints.apiVersions` у каждой поставляемой политики равен `["*"]` по той
же причине: она сопоставляется с объектом независимо от того, какую версию реально вернул кластер.

## `istio.peer-authentication-permissive-mtls`

Помечает `PeerAuthentication`, у которого `spec.mtls.mode` равен `DISABLE` или `PERMISSIVE`
(серьёзность High). Приоритет PeerAuthentication основан на специфичности — объект уровня workload-а
переопределяет объект уровня неймспейса, который переопределяет объект уровня mesh `default` в
корневом неймспейсе — и эта проверка оценивает каждый объект независимо, а не эффективный режим для
всего кластера. Значение по умолчанию `PERMISSIVE` на уровне неймспейса может быть безопасно
переопределено объектом уровня workload-а со значением `STRICT` в другом месте, или наоборот; перед
тем как действовать только на основании этой находки, проверьте приоритет вручную.

## `istio.authorization-policy-no-source-restriction`

Помечает `AuthorizationPolicy` (`action: ALLOW`, явно указанный или по умолчанию) с правилом, у
которого `from` отсутствует или пусто — согласно API, это соответствует запросам из **любого**
источника, ограниченного только `to`/`when`, если они указаны (серьёзность High). Политики с
действием `DENY`/`AUDIT`/`CUSTOM` никогда не помечаются: неограниченный `from` у них не является тем
же видом пробела.

## `istio.authorization-policy-wildcard-path`

Помечает правило ALLOW в `AuthorizationPolicy`, у которого `to[].operation.paths` включает `"*"` или
`"/*"` — предоставляя доступ ко всем HTTP-путям на выбранных workload-ах вместо конкретных эндпоинтов
(серьёзность Medium). Не зависит от проверки ограничения источника выше: у правила может быть корректно
ограниченный `from` для одного вызывающего и при этом он получает доступ ко всем путям.

## `istio.destination-rule-tls-disabled`

Помечает `DestinationRule`, у которого `spec.trafficPolicy.tls.mode` равен `DISABLE` (серьёзность
High). Собственная справка API Istio (`networking/v1alpha3/destination_rule.proto`, перечисление
`TLSmode`): «DISABLE - Do not setup a TLS connection to the upstream endpoint» («не устанавливать
TLS-соединение с восходящим эндпоинтом»). Проверяется только значение по умолчанию верхнего уровня —
`trafficPolicy.portLevelSettings[].tls.mode` и
`subsets[].trafficPolicy(.portLevelSettings[])?.tls.mode` могут переопределять его для каждого
порта/подмножества, та же оговорка «оценивается независимо», что и у всех остальных проверок здесь.

## `istio.gateway-weak-tls-version`

Помечает `Gateway` с сервером, у которого `tls.minProtocolVersion` равен `TLSV1_0` или `TLSV1_1`
(серьёзность Medium). Оба значения реальны и всё ещё принимаются собственным API Istio
(`networking/v1alpha3/gateway.proto`, перечисление `TLSProtocol`), но формально признаны устаревшими
IETF RFC 8996 («Deprecating TLS 1.0 and TLS 1.1») — это единственная проверка `istio.*`, опирающаяся на
внешний протокольный стандарт, а не на собственную документацию Istio, независимо помечающую значение
как небезопасное, тот же паттерн обоснования, который этот инструмент использует в других местах при
отсутствии рекомендаций конкретного вендора (например, NIST SP 800-190 для проверки учётных данных в
ConfigMap).

## `istio.mesh-config-outbound-traffic-policy-allow-any`

Помечает конфигурацию `mesh` в ConfigMap `istio` (текстовый блок YAML, а не отдельное типизированное
поле — собственный, хорошо известный, стабильный по имени runtime-объект Istio, а не CRD), когда
`outboundTrafficPolicy.mode` явно не равен `REGISTRY_ONLY` (серьёзность Medium). Собственная
[справка API](https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/) Istio: «The default
is `ALLOW_ANY`, which permits traffic to unknown destinations» («по умолчанию используется `ALLOW_ANY`,
что разрешает трафик к неизвестным адресатам») — «any traffic to unknown destinations will be allowed»
— в противовес `REGISTRY_ONLY`, где «unknown outbound traffic will be dropped. Traffic destinations
must be explicitly declared into the service registry through ServiceEntry configurations»
(«неизвестный исходящий трафик будет отброшен; адресаты трафика должны быть явно объявлены в реестре
сервисов через конфигурации ServiceEntry»). Помечается как отсутствие поля (значение по умолчанию), так
и явные `ALLOW_ANY`/`ALLOW_ANY_DYNAMIC_DNS` — проходит проверку только явный `REGISTRY_ONLY`.
Проверяет собственный runtime-объект конфигурации компонента, тот же паттерн, что и у проверок ArgoCD
`argocd-cmd-params-cm`/`argocd-rbac-cm`, а не у CRD.

## `istio.destination-rule-tls-insecure-skip-verify`

Помечает `DestinationRule`, у которого `spec.trafficPolicy.tls.insecureSkipVerify` равен `true`
(серьёзность High). Собственная справка API Istio (`networking/v1alpha3/destination_rule.proto`,
`ClientTLSSettings.insecure_skip_verify`): «specifies whether the proxy should skip verifying the CA
signature and SAN for the server certificate corresponding to the host. The default value of this
field is false» («указывает, должен ли прокси пропускать проверку подписи CA и SAN сертификата
сервера, соответствующего хосту; значение по умолчанию для этого поля — false»). Отдельное, более
тонкое понижение защиты по сравнению с `istio.destination-rule-tls-disabled`: TLS всё ещё
согласовывается, но личность пира никогда не проверяется, поэтому соединение тривиально уязвимо для
MITM. Та же оговорка про область действия только верхнего уровня, что и у
`istio.destination-rule-tls-disabled`.

## `istio.sidecar-outbound-traffic-policy-allow-any`

Помечает ресурс `Sidecar`, у которого `spec.outboundTrafficPolicy.mode` явно равен `ALLOW_ANY`
(серьёзность Medium). Та же форма API и обоснование, что и у
`istio.mesh-config-outbound-traffic-policy-allow-any`, но на уровне workload-а, а не всего mesh:
неустановленное значение наследует настройку mesh по умолчанию (уже покрыто той проверкой), поэтому
эта срабатывает только когда ресурс `Sidecar` *явно* переопределяет значение на `ALLOW_ANY` — включая,
в частности, случай, когда он переопределяет значение по умолчанию `REGISTRY_ONLY` для всего mesh,
снова открывая доступ для одного workload-а.

## `istio.request-authentication-fromheaders-no-bearer-prefix`

Помечает `RequestAuthentication`, у которой задан пользовательский `jwtRules[].fromHeaders`, но хотя
бы одна запись не устанавливает `prefix` (или устанавливает его пустым) (серьёзность Medium).
Применяется только когда `fromHeaders` вообще задан — поведение Istio по умолчанию (без
`fromHeaders`) уже ищет `Authorization: Bearer <token>` и не требует явного префикса. Без `prefix`
Istio трактует всё значение заголовка как сырой JWT — заголовок перестаёт следовать стандартному
соглашению `Authorization: Bearer <token>`, из-за чего токен легко спутать с (или переиспользовать
из) другими схемами авторизации/заголовками, не рассчитанными на значения в форме JWT. Перед тем как
считать это реальным пробелом, подтвердите, что пользовательский заголовок действительно должен
нести сырой токен (некоторые исключительно внутренние gateway делают это намеренно) — если да, это
осознанное архитектурное решение, а не недосмотр.

## `istio-analyzer.no-authorization-policy-coverage` (нативный анализатор)

В отличие от девяти VAP-проверок выше, эта реализована как нативный Go-анализатор
([`internal/istio/authzcoverage.go`](../internal/istio/authzcoverage.go)), а не как политика VAP CEL
для одного объекта — отвечает на вопрос «есть ли вообще хоть какое-то покрытие ALLOW
`AuthorizationPolicy` для этого workload'а», требующий сопоставления меток workload'а со всеми
`AuthorizationPolicy` в его неймспейсе — то же межобъектное рассуждение, которое `internal/netpol`
делает для покрытия NetworkPolicy. Помечает (серьёзность High) каждый workload в неймспейсе с
включённым sidecar injection (`istio-injection=enabled` либо `istio.io/rev`), для которого не
находится ни одной `AuthorizationPolicy` с `action: ALLOW` (либо не заданным `action`, что по
умолчанию тоже означает ALLOW) — поведение Istio по умолчанию при отсутствии таких политик
разрешает всё, и только появление ALLOW-политики переключает его на deny-by-default. Политика
только с `DENY`/`AUDIT` **не** засчитывается как покрытие по той же причине. Намеренно узкая
детекция: учитывается только `spec.selector.matchLabels` (или его отсутствие — namespace-wide);
более новый способ выбора через `targetRefs`/`targetRef` (в стиле Gateway API) не симулируется, так
что workload, реально покрытый только через `targetRefs`, даст ложное срабатывание здесь — см.
собственные `VerificationSteps` находки.

## Без сайдкаров (ambient-режим)

Ambient-режим Istio переносит принудительное применение mTLS уровня L4 на `ztunnel` уровня узла и
делает принудительное применение L7 (`to.operation.methods`/`paths`/`hosts`) опциональным через
**waypoint-прокси**, разворачиваемый для каждого workload-а/неймспейса. `AuthorizationPolicy` с
правилами L7, но без развёрнутого waypoint-а для своей цели, вообще не применяется принудительно —
объект существует, выглядит корректно и ничего не делает. У этого инструмента нет способа проверить
развёртывание waypoint-а только по объектам, поэтому он не может отличить «правило L7 применяется» от
«правило L7 молча игнорируется» в ambient-режиме. Если вы используете ambient-режим, проверьте
развёртывание waypoint-а для любого неймспейса/workload-а, упомянутого в находке
`istio.authorization-policy-wildcard-path` или `istio.authorization-policy-no-source-restriction`.

## Рассмотрено и отклонено

- `VirtualService.spec.hosts`, содержащий голый `"*"` — справка API VirtualService документирует хосты
  с wildcard-*префиксом* (`"*.example.com"`) как поддерживаемый паттерн, но не выделяет отдельно голый
  `"*"` как рискованный так же, как источники для других проверок этого инструмента. В текущем виде не
  соответствует планке «прослеживается до конкретной, процитированной строки собственной документации
  проекта».
- Отдельная проверка для `PeerAuthentication.spec.mtls.mode: DISABLE` — не нужна:
  `istio.peer-authentication-permissive-mtls` уже помечает и `DISABLE`, и `PERMISSIVE`.
- Существование/использование `EnvoyFilter` — собственная документация Istio действительно
  предупреждает, что его «нужно использовать с осторожностью» и он может «дестабилизировать весь mesh»,
  но это предупреждение о стабильности самого механизма, а не конкретное плохое *значение* для проверки
  (всё назначение EnvoyFilter — произвольная низкоуровневая конфигурация Envoy). Пометка самого факта
  существования была бы шумом для любого серьёзного развёртывания Istio. Существующей меры снижения
  риска нет; известный пробел.
- `RequestAuthentication`, настроенная без соответствующей принудительно применяющей
  `AuthorizationPolicy` (реальная, часто документируемая ловушка Istio: проверка JWT настроена, но
  фактически никогда не требуется) — требует сопоставления двух отдельных CRD, то же ограничение
  межобъектного сопоставления, что и у пункта про AuthorizationPolicy-на-каждый-неймспейс выше.
- `ServiceEntry.spec.resolution: NONE` — легитимный, распространённый паттерн для инициации TLS/
  прозрачного TCP-прохождения, а не задокументированное небезопасное значение. Отклонено по причинам
  источника, а не безопасности.
