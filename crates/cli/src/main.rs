use clap::{Parser, Subcommand};

mod commands;
mod crypto;
mod keystore;

#[derive(Parser)]
#[command(name = "p47h")]
#[command(version, about = "P47H Policy & Identity CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Policy validation and management
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// DID (Decentralized Identifier) management
    Did {
        #[command(subcommand)]
        command: DidCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Validate a policy file
    Check {
        /// Path to the policy TOML file
        file: String,
    },
}

#[derive(Subcommand)]
enum DidCommands {
    /// Generate a new DID
    New {
        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<String>,

        /// WARNING: UNSAFE - Display secret key in terminal (NOT RECOMMENDED)
        #[arg(long, hide = true)]
        unsafe_show_secret: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Policy { command } => match command {
            PolicyCommands::Check { file } => {
                commands::policy::check(&file)?;
            }
        },
        Commands::Did { command } => match command {
            DidCommands::New {
                output,
                unsafe_show_secret,
            } => {
                commands::did::new(output.as_deref(), unsafe_show_secret)?;
            }
        },
    }

    Ok(())
}
