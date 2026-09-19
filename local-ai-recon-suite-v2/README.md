# Local AI Recon Suite v2

Local-first Recon/Discovery knowledge + RAG + Agent Router + Burp Montoya bridge.


## Recon Intelligence Copilot

The Burp extension can passively observe **in-scope** HTTP traffic without requiring the
operator to paste or select individual requests. The local backend builds an application graph
from observed traffic and generates English-only recon insights.

Pipeline:

```
Burp in-scope traffic
        ↓
Passive observer
        ↓
SQLite application graph
        ↓
Endpoints / parameters / relationships
        ↓
Deterministic hypothesis signals
        ↓
Chroma + hybrid retrieval
        ↓
Ollama Recon Intelligence
        ↓
English recon insight
```

The insight includes:
- application structure and resource families
- relationships between observed pages/endpoints
- repeated parameters and their cross-endpoint usage
- interesting endpoints
- hypothesis candidates with confidence and supporting evidence
- gaps that prevent stronger conclusions
- retrieved knowledge sources

Automatic insight generation is intentionally throttled by `AUTO_INSIGHT_EVERY`
(default: 8 observed requests) so the LLM is used for reasoning rather than per-request parsing.

### Medium knowledge sources

The ingestion pipeline also supports Medium topic RSS feeds for recon and security research,
including Bug Bounty, Reconnaissance, Web Security, Penetration Testing, and Cybersecurity.
Medium documents RSS feeds for topic pages and notes that stories behind its paywall are not
available as full stories through RSS, so the knowledge layer uses only what is publicly available
from the feed/page.

### Useful endpoints

```
GET  /recon/hosts
GET  /recon/<host>
GET  /recon/<host>/candidates
GET  /recon/<host>/insight
POST /recon/<host>/analyze
POST /burp_event
```

## هدف المشروع

- جمع محتوى أمني عام له قيمة تقنية في Recon / Discovery / Security Tooling / API Discovery / Web Security.
- عمل historical backfill أول مرة بدل الاعتماد على آخر RSS entries فقط.
- تحديث incremental لاحقًا بدون إعادة إدخال نفس المحتوى.
- دعم HackerOne Hacktivity العام عبر API credentials اختيارية.
- دعم Bugcrowd public disclosures / CrowdStream فقط.
- فصل المعرفة إلى مجموعات Chroma:
  - recon
  - web_security
  - tooling_development
  - public_disclosures
- تشغيل Agent/Skill prompts محلية بأسلوب مشابه لـ AITMPL، بدون الاعتماد على Claude Code.
- ربط Burp عبر Java Montoya مع Python API محلي.

## 1) البيئة

يفضل JDK 21 لـ Burp extension.

```bash
sudo apt update
sudo apt install -y python3-venv openjdk-21-jdk
```

ثم:

```bash
cd local-ai-recon-suite-v2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Ollama

ثبت Chat model وEmbedding model مناسبين لجهازك.

مثال:

```bash
ollama pull nomic-embed-text
ollama pull qwen2.5-coder:7b
```

تأكد:

```bash
ollama list
```

## 3) إعداد HackerOne

Hacktivity integration اختياري. ضع credentials في البيئة:

```bash
export H1_API_USERNAME="..."
export H1_API_TOKEN="..."
```

ولا تحفظها داخل ملفات git.

## 4) Historical Backfill

أول تشغيل:

```bash
python recon/backfill.py
```

إعدادات مفيدة:

```bash
export RECON_BACKFILL_MAX_DOCS=10000
export RECON_BACKFILL_MAX_PAGES=200
export H1_MAX_PAGES=100
export RECON_MIN_SCORE=12
```

الـbackfill لا يضمن أن كل موقع يحتفظ بتاريخ كامل قابل للاكتشاف؛ يعتمد على RSS/sitemap/public archive المتاح لكل مصدر.

## 5) Build Chroma

```bash
python recon/index_chroma.py
```

بعدها ستجد:

```text
data/chroma/
data/recon_documents.jsonl
data/recon_chunks.jsonl
data/state.json
```

## 6) التشغيل اليومي

```bash
python recon/live_update.py
python recon/index_chroma.py
```

يمكن تركيب timer:

```bash
chmod +x scripts/install_timer.sh
./scripts/install_timer.sh
```

## 7) Local API

```bash
python app.py
```

اختبار:

```bash
curl http://127.0.0.1:5000/health
```

## 8) Burp Extension

ادخل إلى:

```text
burp-extension/
```

ثم:

```bash
chmod +x gradlew
./gradlew clean jar
```

الناتج:

```text
burp-extension/build/libs/burp-recon-ai.jar
```

حمّله من:

```text
Burp -> Extensions -> Installed -> Add -> Java
```

ثم استخدم:

```text
Right click request -> Local Recon AI -> Analyze request
```

## 9) إضافة Agent أو Skill بأسلوب AITMPL

لا نثبت Claude Code داخل المشروع. بدلاً من ذلك نستخدم adapter محلي.

مثال:

```bash
python ai/import_component.py \
  --kind skill \
  --name my-skill \
  --file /path/to/SKILL.md
```

أو:

```bash
python ai/import_component.py \
  --kind agent \
  --name my-agent \
  --file /path/to/agent.md
```

ثم:

```bash
python ai/list_components.py
```

الـadapter يحتفظ بالمحتوى المحلي ويضيف frontmatter محليًا عند الحاجة. لا يتم تنفيذ أوامر Claude Code تلقائيًا.

## مصادر البيانات

المشروع يقسم المحتوى إلى:
- recon: reconnaissance / asset discovery / enumeration / attack-surface
- tooling_development: security automation / scanners / crawlers / Burp / Python / Go
- web_security: web/API testing methodology
- public_disclosures: تقارير منشورة للعامة

المحتوى الخاص أو غير المنشور لا يتم جمعه.

## Safety boundary

هذا المشروع مصمم للبحث/التحليل على أنظمة مصرح باختبارها. الـBurp bridge يرسل الطلب إلى Local AI للتحليل فقط؛ لا يحتوي على وظيفة تلقائية لاستغلال الأهداف.
