# DP-Guard

Архитектура и прототип системы безопасной LLM-оркестрации в AI-native zero-touch 6G сетях с типизированным контролем доступа, дифференциальной приватностью (Differential Privacy) и математической верификацией допустимости действий.

---

## Возможности

- **Мультиагентный рой нейросетей (Multi-Agent Swarm):** Иерархическая координация: Главный LLM-координатор (`LeadOrchestratorAgent`) динамически порождает специализированных автономных субагентов (`ThreatMitigation`, `AnomalyForensics`, `SlicingQoS`), распределяет кванты бюджета приватности ($\sum \varepsilon_i \le \varepsilon_{\text{total}}$) и синтезирует согласованное решение.
- **Локальный анклав телеметрии (Local Edge Enclave):** Строгая изоляция сырых абонентских данных (SUPI, IMSI, IP, дампы пакетов) на локальном узле ядра/радиодоступа. Сырые данные **никогда не передаются в облако**; во внешнюю LLM отправляются исключительно скаляры с шумом Лапласа.
- **Поддержка реального 5G Standalone стенда (Open5GS + UERANSIM):** Адаптер `Live5GTelemetryAdapter` для мониторинга интерфейса `ogstun` и замкнутого управления трафиком через `iptables`/`tc`.
- **Механизм чистого $\varepsilon$-DP (Laplace Mechanism):** Добавление калиброванного шума $\text{Lap}(\Delta_1 / \varepsilon)$ к агрегированным KPI сессий абонентов.
- **Каталог типизированных метрик ($\mathcal{T}$):** 6 типизированных метрик сети с фиксированными $L_1$-чувствительностями $\Delta_1(q)$ и границами $[\varepsilon_{\min}, \varepsilon_{\max}]$.
- **Плоскость типизированных политик (Typed Policy Plane):** Ролевой контроль доступа $\Pi: \text{Role} \to \mathcal{T}$ (`security_operator`, `network_admin`, `readonly_auditor`).
- **Фильтр бюджета приватности (Privacy Filter / Odometer):** Превентивная проверка и списание бюджета $\varepsilon$ для предотвращения утечки информации при адаптивных сериях запросов.
- **Верификатор допустимости (Admissibility Verifier):** Детерминированная проверка безопасности действий LLM $\text{Adm}(\hat{a}, \tilde{z})$ на основе доверительных множеств $B_\beta(\tilde{z})$ с надежностью $1-\beta = 95\%$.
- **Защитный откат (Fail-Safe Fallback):** Автоматическое применение политики *deny-by-default* (`safe_fallback`) при обнаружении аномалий, перерасходе бюджета или галлюцинациях нейросети.
- **Мультипровайдерная интеграция LLM (Proposal Generator):** Поддержка Google Gemini API (`gemini-3.6-flash`), OpenAI API (`gpt-4o-mini`) и автономного Mock-режима со строгой валидацией через JSON Schema.
- **Замкнутый контур управления (Closed-Loop Actuation):** Симуляция и реальное исполнение сетевых управляющих воздействий (`block_traffic`, `isolate_segment`, `rate_limit_slice`) с динамическим изменением состояния сети.
- **Неизменяемый аудит-лог (Audit & Compliance):** Фиксация каждого шага оркестрации, состава субагентов, значений $\varepsilon$, доверительных интервалов и вердиктов верификатора в формате JSONL.

---

## Архитектура проекта

Ниже представлена архитектурная схема DP-Guard, показывающая ключевые плоскости и их взаимодействие:

```
+-------------------------------------------------------------------------------+
|                               OPERATOR INTENT                                 |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
                    +---------------------------------------+
                    |       LEAD COORDINATOR AGENT          |
                    | (Gemini 3.6 Flash / Multi-Agent Swarm)|
                    +-------------------+-------------------+
                                        |  (Spawns Subagents & partitions eps)
        +-------------------------------+-------------------------------+
        |                               |                               |
        v                               v                               v
+-------------------+           +-------------------+           +-------------------+
| Threat Mitigator  |           | Anomaly Forensics |           | Slicing & QoS     |
|     Subagent      |           |     Subagent      |           |     Subagent      |
+---------+---------+           +---------+---------+           +---------+---------+
          |                               |                               |
          +-------------------------------+-------------------------------+
                                          | Swarm Consensus Proposal (a^)
                                          v
+-----------------------+       +-------------------+
|     POLICY PLANE      |       |   VERIFICATION    |
| Typed Policy Pi(Role) |       |       PLANE       |
|   Privacy Filter      |       |  B_beta(z_noisy)  |
+-----------+-----------+       +---------+---------+
            |                             |
            v                             v
+-----------------------+           [ ADMISSIBLE? ]
|  LOCAL EDGE ENCLAVE   |             /         \
| (Raw Telemetry Store) |====(DP)==> /           \
| Open5GS / ogstun / UE |      (YES)/             \(NO)
+-----------------------+          v               v
                              [ Execute ]     [ Safe Fallback ]
                              [ Action  ]     [ (Fail-Safe)   ]
```

### Описание компонентов

| Компонент | Модуль | Описание |
|-----------|--------|----------|
| **Multi-Agent Swarm** | `subagents.py` | Иерархический рой: координатор и профильные субагенты с локальными бюджетами и голосованием. |
| **Live 5G Adapter** | `live_5g_adapter.py` | Интеграция с физическим/виртуальным 5G-стендом (Open5GS + UERANSIM) на интерфейсе `ogstun`. |
| **Local Telemetry Store** | `network_telemetry.py` | Хранение сессий UE строго в локальной памяти; вычисление $q(X)$ без доступа извне. |
| **Telemetry Plane** | `telemetry_plane.py` | Единственная точка доступа к сырым данным; накладывает шум Лапласа $\text{Lap}(\Delta_1 / \varepsilon)$. |
| **Privacy Policy Plane** | `privacy_policy.py` | Контроль ролевого доступа $\Pi(\text{Role})$, проверка допустимости запрашиваемых метрик и действий. |
| **Privacy Accountant** | `privacy_accountant.py` | Учет расхода бюджета приватности $\varepsilon_{\text{spent}} \le \varepsilon_{\text{tot}}$, превентивная блокировка при перерасходе. |
| **Orchestration Plane** | `orchestrator.py` | Координатор замкнутого цикла: Intent $\to$ Swarm $\to$ Policy $\to$ DP Reads $\to$ Verify $\to$ Actuate $\to$ Audit. |
| **LLM Planner** | `openai_planner.py` / `llm_factory.py` | Генератор планов и действий через структурированный JSON Schema (поддержка Google Gemini и OpenAI). |
| **Mock Planner** | `mock_llm.py` | Автономный генератор предложений для оффлайн-демонстраций и тестов без API-ключей. |
| **Admissibility Verifier** | `admissibility_verifier.py` | Математическая проверка безопасности действий с учетом доверительного радиуса шума $t_\beta = b \ln(2/\beta)$. |
| **Action Executor** | `action_executor.py` | Применение команд к сети с обратной связью (`iptables`, `tc`, разрыв сессий). |
| **Audit Log** | `audit_log.py` | Структурированное журналирование всех эпох в формате JSONL для аудита безопасности. |

---

## Требования

- **Python:** 3.10 или выше (протестировано на Python 3.12 / 3.14)
- **Операционная система:** Windows (PowerShell), Linux или macOS
- **Пакетный менеджер:** `pip`

---

## Зависимости

- `numpy` — математические операции и генерация распределения Лапласа
- `openai` — клиент для взаимодействия с OpenAI API и Google Gemini (OpenAI-compatible endpoint)
- `python-dotenv` — загрузка параметров конфигурации из `.env`
- `pytest` — автоматизированное модульное тестирование

---

## Установка

```powershell
# 1. Клонирование репозитория
git clone https://github.com/vanyadingle/DPguardDEMO.git
cd DPguardDEMO

# 2. Создание и активация виртуального окружения
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # В Linux/macOS: source .venv/bin/activate

# 3. Установка зависимостей
pip install -r requirements.txt
```

---

## Конфигурация (`.env`)

Скопируйте шаблон конфигурации:
```powershell
copy .env.example .env
```

Настройте параметры в файле `.env`:

```env
# Выбор провайдера нейросети: "gemini", "openai" или "mock"
LLM_PROVIDER=gemini

# 1. Google Gemini API (Бесплатный ключ на https://aistudio.google.com/)
GEMINI_API_KEY=AIzaSy_ваш_ключ_здесь
GEMINI_MODEL=gemini-2.0-flash

# 2. OpenAI API (https://platform.openai.com/)
OPENAI_API_KEY=sk-ваш_ключ_здесь
OPENAI_MODEL=gpt-4o-mini

# Бюджет дифференциальной приватности
DP_EPSILON_TOTAL=2.0

# Пороги безопасности для Admissibility Verifier
THREAT_SAFETY_THRESHOLD=30.0
ANOMALY_SAFETY_THRESHOLD=40.0
VERIFICATION_BETA=0.05

# Активная роль оператора
DP_GUARD_ROLE=security_operator
```

---

## Запуск и команды

### 1. Запуск автоматических тестов
Проверка всех математических инвариантов и модулей:
```powershell
pytest tests/ -v
```

### 2. Запуск демонстрации мультиагентного роя (Google Gemini)
```powershell
python main.py demo --epochs 3 --llm
```

### 3. Автономный оффлайн-запуск роя без интернета (Mock LLM)
```powershell
python main.py demo --epochs 3 --mock
```

### 4. Запуск в реальном времени на 5G-стенде (Open5GS + UERANSIM)
```powershell
python main.py live-5g --interface ogstun --epochs 3 --simulate-attack
```

### 5. Просмотр журнала аудита в реальном времени
```powershell
Get-Content logs/audit.jsonl -Tail 1 | ConvertFrom-Json | Format-List
```

---

## Каталог метрик телеметрии

Каждая метрика в каталоге имеет строгую глобальную $L_1$-чувствительность $\Delta_1(q)$, используемую для калибровки масштаба шума Лапласа $b = \Delta_1 / \varepsilon$:

| Метрика | Описание | $L_1$-Чувствительность ($\Delta_1$) | Допустимый диапазон $\varepsilon$ |
|---------|----------|:-----------------------------------:|:---------------------------------:|
| `threat_level` | Максимальный уровень угрозы в слайсе $[0, 100]$ | `1.0` | $[0.10, 0.80]$ |
| `active_connections` | Количество активных сессий абонентов | `1.0` | $[0.05, 0.50]$ |
| `anomaly_score` | Доля аномальных сессий $(\%)$ $[0, 100]$ | `5.0` | $[0.10, 0.60]$ |
| `failed_auth_attempts` | Суммарное число сбоев авторизации в слайсе | `1.0` | $[0.05, 0.40]$ |
| `slice_load_percent` | Нагрузка слайса в $\%$ от пропускной способности | `2.0` | $[0.05, 0.40]$ |
| `packet_loss_rate` | Оценка потерь пакетов $(\%)$ $[0, 5]$ | `0.5` | $[0.05, 0.30]$ |

---

## Математические гарантии безопасности

### 1. Дифференциальная приватность (Differential Privacy)
Для каждого запроса $q(X)$ механизм Лапласа генерирует шум:
$$M(X) = q(X) + \eta, \quad \eta \sim \text{Laplace}\left(0, \frac{\Delta_1(q)}{\varepsilon}\right)$$
В силу теоремы о постобработке (*Post-Processing Invariance*), любое действие $\hat{a} = g(\tilde{z}^{(1:k)})$, сгенерированное LLM на основе зашумленных данных $\tilde{z}$, строго удовлетворяет свойству $(\varepsilon_{\text{tot}}, 0)$-DP.

### 2. Верификация допустимости под шумом ($B_\beta(\tilde{z})$)
Для доверительной вероятности $1 - \beta = 0.95$ вычисляется радиус доверительного интервала:
$$t_\beta = b \cdot \ln\left(\frac{2}{\beta}\right) = \frac{\Delta_1(q)}{\varepsilon} \cdot \ln\left(\frac{2}{\beta}\right)$$
Действие $\hat{a}$ допускается к исполнению ($\text{Adm}(\hat{a}, \tilde{z}) = \text{True}$) только в том случае, если наихудшая граница интервала $B_\beta(\tilde{z}) = [\tilde{z} - t_\beta, \tilde{z} + t_\beta]$ удовлетворяет предикату безопасности $\text{Safe}(\hat{a}, z)$. В противном случае выполняется детерминированный `safe_fallback`.

---

## Структура репозитория

```
DP_Guard/
├── main.py                     # Точка входа: 3-эпоховый демонстрационный цикл
├── pytest.ini                  # Конфигурация тестового раннера
├── requirements.txt            # Зависимости проекта
├── .env.example                # Шаблон переменных окружения
├── README.md                   # Документация проекта
├── DEMO_GUIDE.txt              # Пошаговое руководство для демонстрации
├── ALGORITHMS_AND_STATUS.txt   # Математическое описание и статус алгоритмов
├── data/
│   ├── ue_sessions.json        # Структурированные записи сессий UE (raw records)
│   └── network_slices.json     # Топология 6G слайсов и gNodeB
├── logs/
│   └── audit.jsonl             # Структурированный лог аудита (создается при запуске)
├── tests/
│   └── test_dp_guard.py        # Набор модульных тестов (pytest)
└── dp_guard/
    ├── __init__.py
    ├── action_executor.py      # Исполнитель управляющих воздействий на сеть
    ├── admissibility_verifier.py # Верификатор допустимости под DP-неопределенностью
    ├── audit_log.py            # Журналирование эпох в JSONL
    ├── config.py               # Загрузка и валидация конфигурации
    ├── exceptions.py           # Пользовательские исключения
    ├── llm_factory.py          # Фабрика провайдеров LLM (Gemini, OpenAI, Mock)
    ├── mock_llm.py             # Оффлайн Mock-планировщик
    ├── network_telemetry.py    # Агрегатор сырых записей сессий UE
    ├── openai_planner.py       # LLM-планировщик со строгой JSON Schema
    ├── orchestrator.py         # Главный замкнутый цикл оркестрации (Closed-Loop)
    ├── privacy_accountant.py   # Фильтр и счетчик бюджета приватности
    ├── privacy_policy.py       # Типизированная ролевая политика доступа
    ├── telemetry_plane.py      # DP-плоскость телеметрии (шум Лапласа)
    └── types.py                # Типы данных, dataclasses и перечисления
```

