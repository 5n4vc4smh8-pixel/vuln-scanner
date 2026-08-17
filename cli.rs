use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about = "Scanner de Vulnerabilidades Moderno", long_about = None)]
pub struct Cli {
    #[clap(short, long)]
    pub target: Option<String>,

    #[clap(short, long)]
    pub input_file: Option<String>,

    #[clap(short, long)]
    pub output: Option<String>,

    #[clap(short, long, default_value = "1")]
    pub verbose: u8,

    #[clap(long, default_value = "10")]
    pub threads: usize,

    #[clap(long, default_value = "5")]
    pub timeout: u64,

    #[clap(long)]
    pub proxy: Option<String>,

    #[clap(long)]
    pub aggressive: bool,

    #[clap(long)]
    pub cookie: Option<String>,

    #[clap(long)]
    pub header: Option<String>,

    // ===== Autenticação =====
    #[clap(long)]
    pub username: Option<String>,

    #[clap(long)]
    pub password: Option<String>,

    #[clap(long)]
    pub login_url: Option<String>,

    #[clap(long)]
    pub login_data: Option<String>,

    #[clap(long)]
    pub token: Option<String>,

    #[clap(long)]
    pub auth_type: Option<String>,

    #[clap(long)]
    pub confirm_destructive: bool,

    #[clap(long)]
    pub port_scan: bool,

    // ===== Discovery / Crawleamento =====
    #[clap(long)]
    pub crawl: bool,

    #[clap(long, default_value = "2")]
    pub crawl_depth: usize,

    #[clap(long)]
    pub rate_limit: Option<u64>,

    // ===== Formato de relatório =====
    #[clap(long, default_value = "md")]
    pub report_format: String,

    // ===== V7: Painel Web Enterprise =====
    #[clap(long = "web-server")]
    pub web_server: Option<Option<u16>>,

    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    ListVulns,
    UpdatePayloads,
}