# Soul Hunter RS - Missing Features Analysis

## Executive Summary

This document identifies all features present in the source projects (opencode-security-plugin, mobile-security-orchestrator, mobile-security-controller, newbie-rs, tracker-brain-rs) that are **MISSING** from soul-hunter-rs.

**Total Missing Features: 150+**

---

## 🔴 CRITICAL MISSING FEATURES

### 1. Runtime Features (9 Missing)

| Feature | Source Project | Status | Priority |
|---------|---------------|--------|----------|
| **Event Bus** | opencode-security-plugin/runtime/event-bus.ts | ❌ MISSING | CRITICAL |
| **Attack Surface Graph** | opencode-security-plugin/runtime/attack-surface-graph.ts | ❌ MISSING | CRITICAL |
| **Evidence Hash Chain** | opencode-security-plugin/runtime/evidence-hash-chain.ts | ❌ MISSING | CRITICAL |
| **Auto Skill Generator** | opencode-security-plugin/runtime/auto-skill-generator.ts | ❌ MISSING | CRITICAL |
| **Dashboard Server** | opencode-security-plugin/runtime/dashboard-server.ts | ⚠️ PARTIAL | HIGH |
| **Distributed Executor** | opencode-security-plugin/runtime/distributed-executor.ts | ❌ MISSING | CRITICAL |
| **CI/CD Integration** | opencode-security-plugin/runtime/cicd-integration.ts | ❌ MISSING | HIGH |
| **Rule Engine** | opencode-security-plugin/runtime/rule-engine.ts | ❌ MISSING | HIGH |
| **Registries** | opencode-security-plugin/runtime/registries.ts | ❌ MISSING | MEDIUM |

#### Event Bus Details
**File:** `opencode-security-plugin/runtime/event-bus.ts` (323 lines)

**Missing Capabilities:**
- Pub/Sub system for skill-agent communication
- 20+ Event Types:
  - Orchestration: ASSESSMENT_STARTED, ASSESSMENT_COMPLETED, ASSESSMENT_FAILED
  - Phase: PHASE_STARTED, PHASE_COMPLETED, PHASE_FAILED
  - Skill: SKILL_EXECUTING, SKILL_COMPLETED, SKILL_FAILED, SKILL_PROGRESS
  - Finding: FINDING_DISCOVERED, FINDING_CORRELATED, FINDING_UPDATED
  - Risk: RISK_SCORE_UPDATED, RISK_ESCALATED
  - Evidence: EVIDENCE_COLLECTED, EVIDENCE_PROCESSED
  - Auth: AUTH_REQUIRED, AUTH_GRANTED, AUTH_DENIED
- Subscription filtering by event type
- Request-response pattern with timeout
- Message persistence to disk
- Metrics tracking (messages published/delivered/failed, latency)
- Priority levels: low, medium, high, critical

#### Attack Surface Graph Details
**File:** `opencode-security-plugin/runtime/attack-surface-graph.ts` (570 lines)

**Missing Capabilities:**
- Neo4j-style graph database
- Node Types: Component, Endpoint, Permission, DataFlow
- Node Properties: name, type, riskScore, entryPoints, permissions, dataTypes, exposed
- CRUD operations for nodes and relationships
- Path finding between nodes (DFS with depth limit)
- Critical path analysis (highest cumulative risk)
- Graph metrics: node/relationship counts, avg/max risk, density
- Bi-directional adjacency lists
- Export/import to JSON
- Persistence to disk

#### Evidence Hash Chain Details
**File:** `opencode-security-plugin/runtime/evidence-hash-chain.ts` (529 lines)

**Missing Capabilities:**
- SHA-256 hashing with chain linking
- Digital signatures (PKCS8 private key)
- Chain verification:
  - Root hash validation
  - Chain link integrity
  - Signature verification
  - Individual record hash validation
- Export package with files, manifest, chain JSON
- Import from export with verification
- Evidence types: file, log, network, screenshot, finding

---

### 2. Skills (15 Missing)

| Skill | Source Project | Has Code | Priority |
|-------|---------------|----------|----------|
| **mobile-static-analysis** | opencode-security-plugin/skills/ | ✅ Yes | CRITICAL |
| **vulnerability-documentation** | opencode-security-plugin/skills/ | ❌ No | MEDIUM |
| **security-workflow-management** | opencode-security-plugin/skills/ | ❌ No | MEDIUM |
| **risk-context-engine** | opencode-security-plugin/skills/ | ❌ No | HIGH |
| **owasp-mobile-top10** | opencode-security-plugin/skills/ | ❌ No | HIGH |
| **mobile-dynamic-analysis** | opencode-security-plugin/skills/ | ❌ No | CRITICAL |
| **finding-correlation-engine** | opencode-security-plugin/skills/ | ❌ No | HIGH |
| **exploit-generation-management** | opencode-security-plugin/skills/ | ❌ No | MEDIUM |
| **attack-surface-mapper** | opencode-security-plugin/skills/ | ❌ No | HIGH |
| **attack-surface** | tracker-brain-rs/crates/skills/ | ✅ Yes | HIGH |
| **static-analysis** | tracker-brain-rs/crates/skills/ | ✅ Yes | HIGH |
| **dynamic-analysis** | tracker-brain-rs/crates/skills/ | ✅ Yes | HIGH |
| **runtime-analysis** | tracker-brain-rs/crates/skills/ | ✅ Yes | HIGH |
| **correlation** | tracker-brain-rs/crates/skills/ | ✅ Yes | MEDIUM |
| **fuzzing** | tracker-brain-rs/crates/skills/ | ✅ Yes | MEDIUM |

#### Mobile Static Analysis Skill (Full Implementation Missing)
**Source:** `opencode-security-plugin/skills/mobile-static-analysis/index.ts` (642 lines)

**Missing Features:**
- APK/IPA static analysis without execution
- Decompilation with apktool, jadx, aapt
- AndroidManifest.xml parsing
- Dangerous permission detection
- Debuggable flag detection
- Cleartext traffic detection
- Backup enabled detection
- Smali code analysis
- Resource scanning for secrets
- SSL pinning detection
- Root detection bypass checks
- iOS Info.plist analysis
- Entitlements checking
- Binary analysis with otool, class-dump

---

### 3. Tools (8 Missing)

| Tool | Source Project | Priority |
|------|---------------|----------|
| **APK Parser** | opencode-security-plugin/tools/apk-parser/ | CRITICAL |
| **Network Tracer** | opencode-security-plugin/tools/network-tracer/ | HIGH |
| **Log Analyzer** | opencode-security-plugin/tools/log-analyzer/ | MEDIUM |
| **Correlation Matcher** | opencode-security-plugin/tools/correlation-matcher/ | HIGH |
| **Risk Calculator** | opencode-security-plugin/tools/risk-calculator/ | HIGH |
| **Vulnerability Enricher** | opencode-security-plugin/tools/vulnerability-enricher/ | MEDIUM |
| **Auto-Fix Suggester** | opencode-security-plugin/tools/auto-fix-suggester/ | LOW |
| **ML Prioritizer** | opencode-security-plugin/tools/ml-prioritizer/ | MEDIUM |

---

### 4. Agents (7 Missing)

| Agent | Source Project | Has LLM | Priority |
|-------|---------------|---------|----------|
| **Orchestrator Agent** | opencode-security-plugin/agents/ | ✅ Yes | CRITICAL |
| **Static Analysis Agent** | mobile-security-orchestrator/src/agents/static/ | ❌ No | HIGH |
| **Dynamic Analysis Agent** | mobile-security-orchestrator/src/agents/dynamic/ | ✅ Yes | CRITICAL |
| **Network Analysis Agent** | mobile-security-orchestrator/src/agents/network/ | ✅ Yes | HIGH |
| **Crypto Analysis Agent** | mobile-security-orchestrator/src/agents/crypto/ | ✅ Yes | HIGH |
| **Intent Analysis Agent** | mobile-security-orchestrator/src/agents/intent/ | ✅ Yes | HIGH |
| **Fuzzing Agent** | mobile-security-orchestrator/src/agents/fuzzing/ | ✅ Yes | MEDIUM |

#### Orchestrator Agent Details
**Source:** `opencode-security-plugin/agents/orchestrator-agent.ts`

**Missing Capabilities:**
- Input classification (APK, IPA, network-log, source-code, mixed)
- Skill selection based on context
- Pipeline orchestration (7 phases)
- Finding correlation
- Risk evaluation
- Execution planning
- Decision making
- 3 execution modes: quick-scan, standard, comprehensive
- Risk thresholds: Low (30), Medium (60), High (80), Critical (90)

---

### 5. Core Features (12 Missing)

| Feature | Source Project | Priority |
|---------|---------------|----------|
| **Agent Manager** | mobile-security-orchestrator/src/core/agent-manager/ | CRITICAL |
| **Attack Surface Scanner** | mobile-security-orchestrator/src/core/attack-surface-scanner/ | HIGH |
| **Correlation Engine** | mobile-security-orchestrator/src/core/correlation-engine/ | HIGH |
| **Risk Engine** | mobile-security-orchestrator/src/core/risk-engine/ | HIGH |
| **Report Generator** | mobile-security-orchestrator/src/core/report-generator/ | HIGH |
| **Workflow Engine** | mobile-security-orchestrator/src/core/workflow-engine/ | CRITICAL |
| **Finding Manager** | mobile-security-orchestrator/src/core/finding-manager.ts | HIGH |
| **Evidence System** | mobile-security-orchestrator/src/core/evidence/ | HIGH |
| **Skill Adapter** | mobile-security-orchestrator/src/core/skill-adapter.ts | MEDIUM |
| **Skill Registry** | mobile-security-orchestrator/src/core/skill-registry.ts | MEDIUM |
| **Audit Logger** | mobile-security-orchestrator/src/core/audit-logger.ts | MEDIUM |
| **Task Scheduler** | mobile-security-controller/src/core/task-scheduler.ts | HIGH |

#### Workflow Engine Details
**Source:** `mobile-security-orchestrator/src/core/workflow-engine/orchestrator.ts` (239 lines)

**Missing Phases:**
1. Attack Surface Scan
2. Task Generation (priority-based)
3. Agent Execution (parallel/sequential)
4. Finding Collection
5. Correlation
6. Risk Scoring

**Missing Configuration:**
- parallelExecution: boolean
- maxConcurrency: number (default 6)
- timeout: number (default 1 hour)
- enableCorrelation: boolean
- enableRiskScoring: boolean

---

### 6. Analysis Capabilities (25 Missing)

#### Static Analysis Missing Features:
- [ ] Hardcoded secrets detection (API keys, passwords, tokens)
- [ ] Insecure data storage patterns
- [ ] Exported components without permissions
- [ ] Weak cryptographic implementations
- [ ] Debuggable flag detection
- [ ] Cleartext traffic permission
- [ ] Backup enabled flag
- [ ] WebView vulnerabilities
- [ ] Dangerous permissions analysis
- [ ] Hardcoded URLs/endpoints
- [ ] SQL injection patterns
- [ ] Path traversal patterns
- [ ] Insecure random number generation

#### Dynamic Analysis Missing Features:
- [ ] Data exfiltration detection
- [ ] Permission abuse monitoring
- [ ] Network activity analysis
- [ ] Runtime execution detection
- [ ] Sensitive data in memory detection
- [ ] Frida script integration
- [ ] SSL pinning bypass
- [ ] Root detection bypass
- [ ] Debugger detection bypass
- [ ] Crypto monitoring
- [ ] Secret monitoring
- [ ] Intent monitoring

#### Network Analysis Missing Features:
- [ ] Cleartext traffic detection
- [ ] Missing certificate pinning
- [ ] Weak TLS configurations
- [ ] Insecure WebSocket usage
- [ ] Sensitive data in URLs
- [ ] Missing network security config
- [ ] Custom SSL implementations
- [ ] Debug certificates allowed

#### Crypto Analysis Missing Features:
- [ ] Weak algorithms (DES, MD5, SHA1, RC4)
- [ ] Weak key generation
- [ ] Hardcoded encryption keys
- [ ] Insecure random number generation
- [ ] ECB mode usage
- [ ] Missing IV generation
- [ ] Key management issues
- [ ] Custom cryptography detection

#### Intent Analysis Missing Features:
- [ ] Exported activities without permissions
- [ ] Exported services without permissions
- [ ] Exported broadcast receivers without permissions
- [ ] Exported content providers without permissions
- [ ] Intent injection
- [ ] Intent hijacking
- [ ] Pending intent abuse
- [ ] Broadcast receiver vulnerabilities
- [ ] Deep link hijacking
- [ ] Activity hijacking

#### Fuzzing Missing Features:
- [ ] SQL injection detection
- [ ] XSS detection
- [ ] Path traversal detection
- [ ] XXE vulnerabilities
- [ ] Deserialization vulnerabilities
- [ ] WebView JavaScript injection
- [ ] IPC input validation
- [ ] Mutation strategies (BitFlip, ByteFlip, Arithmetic)

---

### 7. LLM Integration Features (8 Missing)

| Feature | Source Project | Status |
|---------|---------------|--------|
| **Multi-Provider Support** | newbie-rs/core/src/provider/ | ❌ MISSING |
| **NVIDIA NIM Integration** | newbie-rs/core/src/provider/nvidia_nim.rs | ❌ MISSING |
| **Ollama Integration** | newbie-rs/core/src/provider/ollama.rs | ❌ MISSING |
| **OpenAI Integration** | newbie-rs/core/src/provider/openai.rs | ❌ MISSING |
| **Anthropic Integration** | newbie-rs/core/src/provider/anthropic.rs | ❌ MISSING |
| **Streaming Responses** | newbie-rs/core/src/inference.rs | ❌ MISSING |
| **Function Calling** | newbie-rs/core/src/provider.rs | ❌ MISSING |
| **Model Routing** | newbie-rs/core/src/inference.rs | ❌ MISSING |

#### Provider Capabilities Missing:
- Streaming - Token-by-token responses
- FunctionCalling - Tool use support
- Vision - Image/multimodal input
- FineTuning - Model customization

---

### 8. Policy & Security Features (6 Missing)

| Feature | Source Project | Priority |
|---------|---------------|----------|
| **Policy Engine** | newbie-rs/core/src/policy.rs | HIGH |
| **WASM Runtime** | newbie-rs/core/src/wasm_runtime.rs | HIGH |
| **Git Worktree Management** | newbie-rs/core/src/worktree.rs | MEDIUM |
| **Agent Sandbox** | mobile-security-controller/src/core/worker-pool.ts | HIGH |
| **Authorization Gate** | mobile-security-controller/src/core/auth-gate.ts | HIGH |
| **Audit Logger** | multiple projects | MEDIUM |

#### Policy Engine Missing Decisions:
- Allow { context }
- Modify { new_input }
- Block { reason }
- Warn { message }
- RequireReview { reviewer }

---

### 9. Advanced Analysis Features (10 Missing)

| Feature | Source Project | Priority |
|---------|---------------|----------|
| **Attack Graph Engine** | tracker-brain-rs/crates/core/src/attack_graph.rs | CRITICAL |
| **Risk Calculator** | tracker-brain-rs/crates/core/src/risk_calculator.rs | HIGH |
| **Confidence Module** | tracker-brain-rs/crates/core/src/confidence.rs | MEDIUM |
| **Evidence Chain** | tracker-brain-rs/crates/core/src/evidence_chain.rs | HIGH |
| **Feedback Loop** | tracker-brain-rs/crates/core/src/feedback_loop.rs | MEDIUM |
| **POC Generator** | tracker-brain-rs/crates/core/src/poc_generator.rs | MEDIUM |
| **Finding Normalizer** | mobile-security-controller/src/core/finding-normalizer.ts | HIGH |
| **Attack Graph (DOT)** | mobile-security-controller/src/core/attack-graph.ts | MEDIUM |
| **Attack Graph (Mermaid)** | mobile-security-controller/src/core/attack-graph.ts | MEDIUM |
| **CVSS Calculator** | mobile-security-controller/src/core/finding-normalizer.ts | HIGH |

---

### 10. Output Formats (5 Missing)

| Format | Source Project | Status |
|--------|---------------|--------|
| **SARIF** | mobile-security-orchestrator/src/core/report-generator/ | ❌ MISSING |
| **PDF** | tracker-brain-rs/crates/core/src/reporting.rs | ❌ MISSING |
| **DOT (Graphviz)** | mobile-security-controller/src/core/attack-graph.ts | ❌ MISSING |
| **Mermaid** | mobile-security-controller/src/core/attack-graph.ts | ❌ MISSING |
| **XML** | multiple projects | ❌ MISSING |

---

### 11. CLI Commands (15 Missing)

| Command | Source Project | Description |
|-----------|---------------|-------------|
| `skills` | mobile-security-orchestrator/src/cli/ | Manage security skills |
| `llm` | newbie-rs/cli/src/main.rs | LLM integration |
| `policy` | newbie-rs/cli/src/main.rs | Run policy evaluation |
| `plugin` | newbie-rs/cli/src/main.rs | Manage plugins |
| `agent` | newbie-rs/cli/src/main.rs | Manage agents |
| `worktree` | newbie-rs/cli/src/main.rs | Manage worktrees |
| `init` | newbie-rs/cli/src/main.rs | Initialize configuration |
| `status` | newbie-rs/cli/src/main.rs | Show system status |
| `surface` | mobile-security-orchestrator/src/cli/ | Scan attack surface |
| `agents` | mobile-security-orchestrator/src/cli/ | List available agents |
| `report` | mobile-security-orchestrator/src/cli/ | Generate report |
| `server` | mobile-security-orchestrator/src/cli/ | Start API server |
| `run-skill` | tracker-brain-rs/crates/cli/ | Run specific skill |
| `list-skills` | tracker-brain-rs/crates/cli/ | List available skills |
| `validate` | tracker-brain-rs/crates/cli/ | Validate configuration |

---

### 12. Dashboard Features (20 Missing)

| Feature | Source | Priority |
|---------|--------|----------|
| **Real-time WebSocket** | opencode-security-plugin/runtime/dashboard-server.ts | CRITICAL |
| **Assessment State Tracking** | opencode-security-plugin/runtime/dashboard-server.ts | HIGH |
| **Phase Progress Visualization** | opencode-security-plugin/runtime/dashboard-server.ts | HIGH |
| **Skill Progress (0-100%)** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Event Broadcasting** | opencode-security-plugin/runtime/dashboard-server.ts | HIGH |
| **Client Commands** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Heartbeat/Ping-Pong** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Statistics Cards** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Assessment Cards** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Risk Level Styling** | opencode-security-plugin/runtime/dashboard-server.ts | LOW |
| **Real-time Event Log** | opencode-security-plugin/runtime/dashboard-server.ts | MEDIUM |
| **Project Management** | FEATURE REQUEST | HIGH |
| **New Assessment Wizard** | FEATURE REQUEST | HIGH |
| **Tool Configuration UI** | FEATURE REQUEST | MEDIUM |
| **Agent Management UI** | FEATURE REQUEST | MEDIUM |
| **System Settings UI** | FEATURE REQUEST | MEDIUM |
| **Monitoring Dashboard** | FEATURE REQUEST | MEDIUM |
| **Finding Details View** | FEATURE REQUEST | HIGH |
| **Report Export UI** | FEATURE REQUEST | MEDIUM |
| **User Management** | FEATURE REQUEST | LOW |

---

### 13. CI/CD Integration (5 Missing)

| Provider | Source Project | Features |
|----------|---------------|----------|
| **GitHub Actions** | opencode-security-plugin/runtime/cicd-integration.ts | PR comments, check runs, inline annotations |
| **GitLab CI** | opencode-security-plugin/runtime/cicd-integration.ts | MR comments, status |
| **Jenkins** | opencode-security-plugin/runtime/cicd-integration.ts | Build artifacts, descriptions |
| **Azure DevOps** | opencode-security-plugin/runtime/cicd-integration.ts | PR threads, status |
| **CircleCI** | opencode-security-plugin/runtime/cicd-integration.ts | Artifacts, markdown summary |

---

### 14. External Tool Integrations (12 Missing)

| Tool | Purpose | Source |
|------|---------|--------|
| **aapt/aapt2** | Android resource extraction | opencode-security-plugin |
| **apktool** | APK disassembly | opencode-security-plugin |
| **jadx** | APK decompilation | opencode-security-plugin |
| **androguard** | Android analysis | opencode-security-plugin |
| **Frida** | Runtime instrumentation | tracker-brain-rs |
| **Objection** | Runtime exploration | tracker-brain-rs |
| **mitmproxy** | MITM traffic interception | tracker-brain-rs |
| **tshark** | PCAP analysis | tracker-brain-rs |
| **drozer** | Android security framework | tracker-brain-rs |
| **Burp Suite** | Web proxy for API testing | tracker-brain-rs |
| **adb** | Android device communication | tracker-brain-rs |
| **class-dump/otool** | iOS binary analysis | opencode-security-plugin |

---

## 📊 Summary Statistics

### By Category:

| Category | Count | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| **Runtime Features** | 9 | 6 | 2 | 1 | 0 |
| **Skills** | 15 | 5 | 6 | 3 | 1 |
| **Tools** | 8 | 1 | 4 | 2 | 1 |
| **Agents** | 7 | 2 | 4 | 1 | 0 |
| **Core Features** | 12 | 3 | 8 | 1 | 0 |
| **Analysis Capabilities** | 25 | 8 | 12 | 4 | 1 |
| **LLM Integration** | 8 | 2 | 4 | 2 | 0 |
| **Policy & Security** | 6 | 2 | 3 | 1 | 0 |
| **Advanced Features** | 10 | 2 | 5 | 3 | 0 |
| **Output Formats** | 5 | 0 | 2 | 2 | 1 |
| **CLI Commands** | 15 | 0 | 5 | 7 | 3 |
| **Dashboard Features** | 20 | 2 | 8 | 7 | 3 |
| **CI/CD Integration** | 5 | 0 | 3 | 2 | 0 |
| **External Tools** | 12 | 3 | 6 | 3 | 0 |
| **TOTAL** | **157** | **36** | **72** | **39** | **10** |

### By Source Project:

| Project | Missing Features |
|---------|-----------------|
| opencode-security-plugin | 45 |
| mobile-security-orchestrator | 38 |
| mobile-security-controller | 32 |
| tracker-brain-rs | 28 |
| newbie-rs | 14 |

---

## 🎯 Implementation Priority

### Phase 1: Critical (36 features)
1. Event Bus
2. Attack Surface Graph
3. Evidence Hash Chain
4. Auto Skill Generator
5. Distributed Executor
6. Mobile Static Analysis Skill (full)
7. Mobile Dynamic Analysis Skill
8. Orchestrator Agent
9. Agent Manager
10. Workflow Engine
11. Attack Graph Engine
12. All 6 Analysis Agents (Static, Dynamic, Network, Crypto, Intent, Fuzzing)

### Phase 2: High Priority (72 features)
- Risk Engine
- Correlation Engine
- Report Generator
- Task Scheduler
- All LLM Providers
- Policy Engine
- CI/CD Integrations
- Dashboard real-time features

### Phase 3: Medium Priority (39 features)
- Advanced analysis features
- Additional output formats
- Extended CLI commands
- Tool configurations
- Monitoring features

### Phase 4: Low Priority (10 features)
- Documentation-only skills
- Nice-to-have dashboard features
- Extended export formats

---

## 📝 Notes

- **Total Lines of Code in Source Projects:** ~15,000+ lines
- **Current soul-hunter-rs Lines:** ~50,000 lines
- **Estimated Additional Lines Needed:** ~25,000-30,000 lines
- **Estimated Implementation Time:** 4-6 weeks with full team

---

*Generated: 2026-04-21*
*Analysis based on: opencode-security-plugin, mobile-security-orchestrator, mobile-security-controller, newbie-rs, tracker-brain-rs*
