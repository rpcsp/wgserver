pub mod ip_forwarding;

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};

use crate::config::{ConfigError, ServerConfig};

pub struct WgService {
    tunnel_name: String,
}
impl WgService {
    pub fn from_config(config: &ServerConfig) -> Self {
        WgService {
            tunnel_name: config.tunnel_name().to_string(),
        }
    }

    /// The systemd unit that runs this tunnel, e.g. wg-quick@wg0.service.
    pub fn systemd_unit_name(self) -> String {
        format!("wg-quick@{}.service", self.tunnel_name)
    }

    pub fn restart(self) -> Result<(), ConfigError> {
        ip_forwarding::enable()?;
        let unit = self.systemd_unit_name();
        run_command("systemctl", &["enable", &unit], None)?;
        run_command("systemctl", &["daemon-reload"], None)?;
        run_command("systemctl", &["restart", &unit], None)?;
        Ok(())
    }

    pub fn print_status(self) {
        println!("Checking wireguard service...");
        // `systemctl status` exits with non-zero code for units that are stopped
        match run_command_ignoring_status("systemctl", &["status", &self.systemd_unit_name()]) {
            Ok(output) if !output.is_empty() => println!("{output}"),
            Ok(_) => println!("No output from 'systemctl status'."),
            Err(e) => println!("Error: {e}"),
        }
    }
}

pub mod generate_key {
    use super::{ConfigError, run_command};

    pub fn public(private: &str) -> Result<String, ConfigError> {
        run_command("wg", &["pubkey"], Some(private)).and_then(validate_wg_key)
    }

    pub fn private() -> Result<String, ConfigError> {
        run_command("wg", &["genkey"], None).and_then(validate_wg_key)
    }

    pub fn preshared() -> Result<String, ConfigError> {
        run_command("wg", &["genpsk"], None).and_then(validate_wg_key)
    }

    fn validate_wg_key(key: String) -> Result<String, ConfigError> {
        match key.len() {
            44 => Ok(key),
            _ => Err(ConfigError::KeyGeneration(format!(
                "Unexpected 'wg' output: {key:?}"
            ))),
        }
    }
}

/// Create a temporary config file with correct permissions and content
/// Then, replace the target config file
pub fn write_config_file(path: &str, content: &str) -> Result<(), ConfigError> {
    fn io_err(context: &str, path: &str, source: io::Error) -> ConfigError {
        ConfigError::Io {
            context: context.to_string(),
            path: path.to_string(),
            source,
        }
    }
    // Create new temp file with permission 600
    // The process id keeps the name unique
    let temp_path = format!("{path}.tmp.{}", std::process::id());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600) // Applies to new files only
        .open(&temp_path)
        .map_err(|e| io_err("Error creating temporary config file", &temp_path, e))?;
    // Write content to file
    file.write_all(content.as_bytes())
        .map_err(|e| io_err("Error writing to config file", &temp_path, e))?;
    // Sync the file that was written
    file.sync_all()
        .map_err(|e| io_err("Error syncing config file", &temp_path, e))?;
    if let Err(e) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(io_err("Error replacing config file", path, e));
    }
    // Sync the directory that was written
    if let Ok(d) = fs::File::open(Path::new(path).parent().unwrap_or(Path::new("."))) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn run_command(program: &str, args: &[&str], input: Option<&str>) -> Result<String, ConfigError> {
    let output = spawn_and_wait(program, args, input)?;
    if !output.status.success() {
        return Err(ConfigError::RunCommand(format!(
            "Command '{} {}' failed: {}",
            program,
            args.join(" "),
            read_output(&output.stderr)
        )));
    }
    Ok(read_output(&output.stdout))
}

/// Run a command and return its stdout whatever the exit status is, for
/// commands that report useful output while exiting non-zero.
fn run_command_ignoring_status(program: &str, args: &[&str]) -> Result<String, ConfigError> {
    let output = spawn_and_wait(program, args, None)?;
    Ok(read_output(&output.stdout))
}

fn spawn_and_wait(
    program: &str,
    args: &[&str],
    input: Option<&str>,
) -> Result<Output, ConfigError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ConfigError::RunCommand(format!("Failed to run '{program}': {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ConfigError::RunCommand(format!("Failed to write to '{program}' stdin")))?;

    if let Some(data) = input {
        stdin
            .write_all(data.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|e| {
                ConfigError::RunCommand(format!("Failed to send input to '{program}': {e}"))
            })?
    }
    // Drop stdin before calling wait_with_output
    drop(stdin);

    child
        .wait_with_output()
        .map_err(|e| ConfigError::RunCommand(format!("Command '{program}' failed: {e}")))
}

fn read_output(output: &[u8]) -> String {
    String::from_utf8_lossy(output).trim().to_string()
}

/// Run command ip route get 198.51.100.1 and get the output interface
///
/// This is a best effort approach and may not work in some situations.
/// Note: RFC 5737 describes IPv4 Address Blocks Reserved for Documentation
/// Example:
/// 198.51.100.1 via 192.168.5.1 dev wlp192s0 src 192.168.5.9 uid 1000
///    cache
pub fn get_default_interface() -> Result<String, ConfigError> {
    let rfc_5737_ip = "198.51.100.1";
    let output = run_command("ip", &["route", "get", rfc_5737_ip], None)?;
    let mut dev_found = false;
    let mut dev: Option<&str> = None;
    for word in output.split_whitespace() {
        if dev_found {
            dev = Some(word);
            break;
        }
        dev_found = word == "dev";
    }

    match dev {
        Some("lo") => Err(ConfigError::Parsing(format!(
            "Cannot use interface from 'ip route get' output {output:?}"
        ))),
        Some(iface) => Ok(iface.to_string()),
        None => Err(ConfigError::Parsing(format!(
            "Cannot obtain interface from 'ip route get' output {output:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::WgService;
    use crate::config::tests::test_server;

    #[test]
    fn unit_is_named_after_the_config_file_not_the_uplink() {
        let service = WgService::from_config(&test_server());
        assert_eq!(service.systemd_unit_name(), "wg-quick@wg0.service");
    }
}
