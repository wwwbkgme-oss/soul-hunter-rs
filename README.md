# Soul Hunter RS

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/soul-hunter/soul-hunter-rs)

> **Unified Security Analysis Platform** - Merging the best of newbie-rs, tracker-brain-rs, and zero-hero-rs

Soul Hunter RS is a production-ready security analysis platform for mobile applications (Android, iOS) and IoT firmware. It combines static analysis, dynamic analysis, network analysis, and AI-powered insights into a unified, extensible framework.

## Features

### Core Capabilities

- **Multi-Platform Analysis**: Android (APK/AAB), iOS (IPA), IoT firmware
- **Static Analysis**: Pattern-based code analysis, secret detection, vulnerability scanning
- **Dynamic Analysis**: Runtime behavior monitoring, network traffic analysis
- **Network Security**: TLS/SSL configuration analysis, certificate pinning detection
- **Cryptographic Analysis**: Weak algorithm detection, key management issues
- **Attack Graph Generation**: Visualize attack paths and critical vulnerabilities
- **Evidence Chain**: Cryptographic proof of findings with Merkle trees
- **Risk Scoring**: CVSS v3.1 and ML-enhanced risk calculation

### Advanced Features

- **WASM Sandbox**: Execute analysis skills in isolated WebAssembly runtime
- **Distributed Execution**: Scale across multiple workers with Redis/NATS backends
- **Real-time Dashboard**: WebSocket-based live monitoring
- **Policy Engine**: WASM and Rego (OPA) policy enforcement
- **LLM Integration**: Ollama, OpenAI, and Anthropic support
- **Event Bus**: Async pub/sub for component communication
- **Circuit Breaker**: Fault tolerance and automatic recovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Soul Hunter RS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │   sh-cli    │  │ sh-dashboard│  │sh-server    │  │  sh-policy  │       │
│  │  (Binary)   │  │  (Web UI)   │  │  (REST API) │  │ (Enforcement)│      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │
│         │                │                │                │                │
│         └────────────────┴────────────────┴────────────────┘                │
│                                    │                                       │
│                           ┌────────▼────────┐                            │
│                           │    sh-core      │                            │
│                           │  (Orchestrator) │                            │
│                           └────────┬────────┘                            │
│                                    │                                       │
│  ┌────────────────────────────────┼────────────────────────────────┐   │
│  │                         sh-orchestrator                           │   │
│  │  (MVCC, Work-Stealing, Hooks, Session Pool, Circuit Breaker)     │   │
│  └────────────────────────────────┬────────────────────────────────┘   │
│                                   │                                       │
│  ┌──────────┬──────────┬──────────┼──────────┬──────────┬──────────┐   │
│  │          │          │          │          │          │          │   │
│  ▼          ▼          ▼          ▼          ▼          ▼          ▼   │
│ ┌────┐   ┌────┐   ┌────┐   ┌────┐   ┌────┐   ┌────┐   ┌────┐   ┌────┐│
│ │sh- │   │sh- │   │sh- │   │sh- │   │sh- │   │sh- │   │sh- │   │sh- ││
│ │agents│  │skills│  │tools │  │graph│  │risk │  │finding│ │evidence│ │wasm││
│ └────┘   └────┘   └────┘   └────┘   └────┘   └────┘   └────┘   └────┘│
│                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │sh-scheduler│ │sh-worker │  │sh-executor│ │sh-event-bus│            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘             │
│                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │
│  │sh-platform│  │sh-llm   │  │sh-distributed│                       │
│  └──────────┘  └──────────┘  └──────────┘                          │
└──────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/soul-hunter/soul-hunter-rs.git
cd soul-hunter-rs

# Build the project
cargo build --release

# Run tests
cargo test
```

### CLI Usage

```bash
# Analyze an Android APK
soul-hunter analyze /path/to/app.apk --static-analysis --network-analysis

# Run full assessment with dashboard
soul-hunter assess /path/to/app.apk --dashboard --dashboard-port 8080

# Start the web dashboard
soul-hunter dashboard --port 8080

# Start the API server
soul-hunter server --port 3000

# List available skills
soul-hunter skills list

# Run a specific skill
soul-hunter skills run static-analysis /path/to/app.apk

# Chat with LLM
soul-hunter llm chat --model llama2 "Analyze this code for vulnerabilities"

# Generate report
soul-hunter report findings.json --output report.html --format html
```

### Server Usage

```bash
# Start the REST API server
soul-hunter-server --port 3000 --host 0.0.0.0

# With CORS enabled
soul-hunter-server --port 3000 --cors

# With static files
soul-hunter-server --port 3000 --static-dir ./dashboard/dist
```

## API Endpoints

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/status` | System status |
| GET | `/api/v1/assessments` | List assessments |
| POST | `/api/v1/assessments` | Create assessment |
| GET | `/api/v1/assessments/:id` | Get assessment |
| POST | `/api/v1/assessments/:id/start` | Start assessment |
| POST | `/api/v1/assessments/:id/cancel` | Cancel assessment |
| GET | `/api/v1/findings` | List findings |
| GET | `/api/v1/agents` | List agents |
| GET | `/api/v1/skills` | List skills |
| WS | `/ws` | WebSocket endpoint |

### WebSocket Events

```json
// Subscribe to events
{"type": "subscribe", "session_id": "uuid"}

// Receive events
{"type": "event", "data": {...}}

// Receive metrics
{"type": "metrics", "data": {...}}
```

## Configuration

Create a `config.yaml` file:

```yaml
# Server configuration
server:
  port: 3000
  host: "127.0.0.1"
  cors: true

# Analysis configuration
analysis:
  max_workers: 8
  timeout_seconds: 300
  enable_evidence_chain: true
  enable_attack_graph: true

# LLM configuration
llm:
  provider: ollama
  model: llama2
  base_url: http://localhost:11434

# Distributed configuration
distributed:
  backend: redis
  redis_url: redis://localhost:6379

# Dashboard configuration
dashboard:
  port: 8080
  max_connections: 100
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| `sh-types` | Core type definitions |
| `sh-core` | Orchestration engine |
| `sh-orchestrator` | Advanced orchestration (MVCC, work-stealing) |
| `sh-agents` | Security analysis agents |
| `sh-skills` | Analysis skills framework |
| `sh-tools` | APK and security tools |
| `sh-graph` | Attack graph database |
| `sh-risk` | Risk scoring engine |
| `sh-finding` | Finding processing and correlation |
| `sh-evidence` | Cryptographic evidence chain |
| `sh-wasm` | WASM sandbox runtime |
| `sh-scheduler` | Job scheduler |
| `sh-worker` | Worker pool management |
| `sh-executor` | Job execution engine |
| `sh-event-bus` | Event bus system |
| `sh-platform` | Platform adapters |
| `sh-llm` | LLM integration |
| `sh-policy` | Policy enforcement |
| `sh-distributed` | Distributed execution |
| `sh-dashboard` | Web dashboard |
| `sh-cli` | Command-line interface |

## Development

### Building

```bash
# Build all crates
cargo build --workspace

# Build with specific features
cargo build --features full

# Build release
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run integration tests
cargo test --test integration_test

# Run with coverage
cargo tarpaulin --out Html
```

### Documentation

```bash
# Generate documentation
cargo doc --workspace --no-deps

# Serve documentation
cargo doc --open
```

## Examples

### Custom Skill

```rust
use sh_skills::prelude::*;

#[derive(Debug)]
struct MySkill;

#[async_trait]
impl SecuritySkill for MySkill {
    fn id(&self) -> SkillId {
        uuid::Uuid::new_v4()
    }

    fn name(&self) -> &str {
        "my_custom_skill"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        // Your analysis logic here
        let findings = vec![];

        Ok(SkillResult::new(self.id(), ctx.task_id)
            .with_findings(findings))
    }
}
```

### Custom Agent

```rust
use sh_agents::prelude::*;

#[derive(Debug)]
struct MyAgent {
    base: AgentBase,
}

#[async_trait]
impl SecurityAgent for MyAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Static
    }

    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        // Your agent logic here
        let findings = FindingCollection::default();

        Ok(AgentResult::success(
            context.task_id,
            self.id(),
            findings,
            1000,
        ))
    }
}
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT OR Apache-2.0 license - see the [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) files for details.

## Acknowledgments

Soul Hunter RS is the unified evolution of three security analysis projects:

- **newbie-rs**: LLM-powered security analysis
- **tracker-brain-rs**: Mobile security assessment platform
- **zero-hero-rs**: Advanced vulnerability research framework

## Support

- 📖 [Documentation](https://docs.soul-hunter.dev)
- 💬 [Discussions](https://github.com/soul-hunter/soul-hunter-rs/discussions)
- 🐛 [Issue Tracker](https://github.com/soul-hunter/soul-hunter-rs/issues)
- 📧 [Email](mailto:support@soul-hunter.dev)

---

**Made with ❤️ by the Soul Hunter Team**
#   s o u l - h u n t e r - r s  
 