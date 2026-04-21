//! Soul Hunter CLI - Production Ready
//! 
//! Unified command-line interface merging commands from:
//! - newbie-rs: llm, server commands
//! - tracker-brain-rs: analyze, skills commands
//! - zero-hero-rs: assess, dashboard commands

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{error, info};

mod commands;

use commands::analyze::AnalyzeCommand;
use commands::assess::AssessCommand;
use commands::dashboard::DashboardCommand;
use commands::report::ReportCommand;
use commands::server::ServerCommand;
use commands::skills::SkillsCommand;

/// Soul Hunter - Unified Security Analysis Platform
#[derive(Parser)]
#[command(name = "soul-hunter")]
#[command(about = "Unified Security Analysis Platform")]
#[command(version = "0.1.0")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze target with specific analysis types
    #[command(alias = "a")]
    Analyze(AnalyzeArgs),

    /// Run full security assessment
    #[command(alias = "as")]
    Assess(AssessArgs),

    /// Start web dashboard
    #[command(alias = "d")]
    Dashboard(DashboardArgs),

    /// Generate report from findings
    #[command(alias = "r")]
    Report(ReportArgs),

    /// Start API server
    #[command(alias = "s")]
    Server(ServerArgs),

    /// Manage security skills
    #[command(alias = "sk")]
    Skills(SkillsArgs),

    /// LLM integration commands
    #[command(alias = "llm")]
    Llm(LlmArgs),
}

#[derive(Parser)]
struct AnalyzeArgs {
    /// Target file or directory
    #[arg(value_name = "TARGET")]
    target: PathBuf,

    /// Enable static analysis
    #[arg(long)]
    static_analysis: bool,

    /// Enable dynamic analysis
    #[arg(long)]
    dynamic_analysis: bool,

    /// Enable network analysis
    #[arg(long)]
    network_analysis: bool,

    /// Enable crypto analysis
    #[arg(long)]
    crypto_analysis: bool,

    /// Enable intent analysis
    #[arg(long)]
    intent_analysis: bool,

    /// Enable all analysis types
    #[arg(short, long)]
    all: bool,

    /// Output file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum)]
    output_format: Option<OutputFormat>,

    /// Number of workers
    #[arg(short, long, default_value = "4")]
    workers: usize,
}

#[derive(Parser)]
struct AssessArgs {
    /// Target file or directory
    #[arg(value_name = "TARGET")]
    target: PathBuf,

    /// Enable dashboard
    #[arg(long)]
    dashboard: bool,

    /// Dashboard port
    #[arg(long, default_value = "8080")]
    dashboard_port: u16,

    /// Output file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    output_format: OutputFormat,

    /// Enable evidence chain
    #[arg(long)]
    evidence: bool,

    /// Enable attack graph
    #[arg(long)]
    attack_graph: bool,

    /// Number of workers
    #[arg(short, long, default_value = "8")]
    workers: usize,
}

#[derive(Parser)]
struct DashboardArgs {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Enable WebSocket
    #[arg(long)]
    websocket: bool,

    /// WebSocket port
    #[arg(long, default_value = "8081")]
    websocket_port: u16,
}

#[derive(Parser)]
struct ReportArgs {
    /// Input findings file
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output file
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    /// Report format
    #[arg(short, long, value_enum, default_value = "html")]
    format: ReportFormat,

    /// Template file
    #[arg(long, value_name = "FILE")]
    template: Option<PathBuf>,
}

#[derive(Parser)]
struct ServerArgs {
    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Enable CORS
    #[arg(long)]
    cors: bool,

    /// API key for authentication
    #[arg(long, value_name = "KEY")]
    api_key: Option<String>,
}

#[derive(Parser)]
struct SkillsArgs {
    #[command(subcommand)]
    command: SkillsCommands,
}

#[derive(Subcommand)]
enum SkillsCommands {
    /// List available skills
    List,
    /// Run a specific skill
    Run {
        /// Skill name
        #[arg(value_name = "SKILL")]
        skill: String,

        /// Target file
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show skill info
    Info {
        /// Skill name
        #[arg(value_name = "SKILL")]
        skill: String,
    },
}

#[derive(Parser)]
struct LlmArgs {
    #[command(subcommand)]
    command: LlmCommands,
}

#[derive(Subcommand)]
enum LlmCommands {
    /// Chat with LLM
    Chat {
        /// Model to use
        #[arg(short, long, default_value = "llama2")]
        model: String,

        /// Message to send
        #[arg(value_name = "MESSAGE")]
        message: String,
    },
    /// List available models
    List,
    /// Start LLM server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "11434")]
        port: u16,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Yaml,
    Sarif,
    Html,
    Markdown,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReportFormat {
    Json,
    Html,
    Markdown,
    Sarif,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Soul Hunter v0.1.0");

    match cli.command {
        Commands::Analyze(args) => {
            commands::analyze::execute(args).await?;
        }
        Commands::Assess(args) => {
            commands::assess::execute(args).await?;
        }
        Commands::Dashboard(args) => {
            commands::dashboard::execute(args).await?;
        }
        Commands::Report(args) => {
            commands::report::execute(args).await?;
        }
        Commands::Server(args) => {
            commands::server::execute(args).await?;
        }
        Commands::Skills(args) => {
            commands::skills::execute(args).await?;
        }
        Commands::Llm(args) => {
            commands::llm::execute(args).await?;
        }
    }

    Ok(())
}
