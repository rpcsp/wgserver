mod cli;
mod config;
mod custom;
mod qr;
mod system;

use crate::{
    config::ServerConfig,
    qr::qrcode_string,
    system::{WgService, ip_forwarding},
};
use clap::Parser;
use std::{error::Error, process::exit};

/// Execute the several actions supported by the tool
fn run(action: cli::Action, path: &str) -> Result<(), Box<dyn Error>> {
    match action {
        cli::Action::Init(cli_init) => {
            let server_config = ServerConfig::init(cli_init, path)?;
            server_config.save()?;
            print!("{}", server_config.file_content())
        }
        cli::Action::Add(cli) => {
            let mut server_config = ServerConfig::load(path)?;
            let peer_config = server_config.add_peer(cli)?;
            server_config.save()?;
            println!("{}", peer_config);
            eprintln!("{}", qrcode_string(&peer_config)?);
        }
        cli::Action::Remove(cli) => ServerConfig::load(path)?.remove_peer(&cli.name)?.save()?,
        cli::Action::Print => print!("{}", ServerConfig::load(path)?.file_content()),
        cli::Action::Parsed => println!("{:#?}", ServerConfig::load(path)?),
        cli::Action::List => ServerConfig::load(path)?.print_peers(),
        cli::Action::Restart => WgService::from_config(&ServerConfig::load(path)?).restart()?,
        cli::Action::Status => {
            let server_config = ServerConfig::load(path)?;
            WgService::from_config(&server_config).print_status();
            ip_forwarding::print_status();
        }
    }
    Ok(())
}

fn main() {
    let cli = cli::Args::parse();
    if let Err(e) = run(cli.action, &cli.config) {
        eprintln!("{e}");
        exit(1);
    }
}
