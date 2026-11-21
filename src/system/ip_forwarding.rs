use super::{run_command, write_config_file};
use crate::config::ConfigError;

const SYSCTL_CONFIG: &str = "/etc/sysctl.d/99-wireguard.conf";
const KEY: &str = "net.ipv4.ip_forward";

pub fn print_status() {
    match is_enabled() {
        Ok(true) => println!("IPv4 forwarding enabled... yes\n"),
        Ok(false) => println!("IPv4 forwarding enabled... no\n"),
        Err(e) => println!("Error: {}", e),
    }
}

pub fn enable() -> Result<(), ConfigError> {
    if !is_enabled()? {
        println!("Enabling IP forwarding...");
        run_command("sysctl", &["-w", &format!("{}=1", KEY)], None)?;
    }
    if !is_persisted() {
        println!("Persisting IP forwarding...");
        persist()?;
    }
    Ok(())
}

/// Check if IPv4 forwarding is enabled.
pub fn is_enabled() -> Result<bool, ConfigError> {
    let output = run_command("sysctl", &[KEY], None)?;
    let enabled =
        output.contains(&format!("{}=1", KEY)) || output.contains(&format!("{} = 1", KEY));
    Ok(enabled)
}

/// Check the persisted value, ignoring comments
fn get_persisted_value(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if is_comment(line) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == KEY
        {
            return value.trim().parse().ok();
        }
    }
    None
}

/// Check if the persistent config already enables ipv4 forwarding.
fn is_persisted() -> bool {
    let config = std::fs::read_to_string(SYSCTL_CONFIG).unwrap_or_default();
    get_persisted_value(&config) == Some("1".to_string())
}

/// Set `KEY = 1` in sysctl file content, replacing any existing value
/// or appending the key/value when it is missing.
fn update_config_to_persist(content: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
    let mut found = false;
    for line in &mut lines {
        let trimmed = line.trim();
        if is_comment(trimmed) {
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=')
            && key.trim() == KEY
        {
            *line = format!("{KEY} = 1");
            found = true;
        }
    }
    if !found {
        lines.push(format!("{KEY} = 1"));
    }
    let mut result = lines.join("\n");
    result.push('\n');
    result
}

/// Ensure a sysctl value is set persistently.
fn persist() -> Result<(), ConfigError> {
    let config = std::fs::read_to_string(SYSCTL_CONFIG).unwrap_or_default();
    write_config_file(SYSCTL_CONFIG, &update_config_to_persist(&config))
}

fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with(';')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_value_set_in_a_sysctl_file() {
        assert_eq!(
            get_persisted_value("net.ipv4.ip_forward = 1\n"),
            Some("1".to_string())
        );
        assert_eq!(
            get_persisted_value("net.ipv4.ip_forward=0\n"),
            Some("0".to_string())
        );
        assert_eq!(get_persisted_value(""), None);
    }

    #[test]
    fn ignores_comments_and_other_keys() {
        let content = "# net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 1\n";
        assert_eq!(get_persisted_value(content), None);
    }

    #[test]
    fn appends_the_key_when_it_is_absent() {
        assert_eq!(
            update_config_to_persist("net.ipv4.conf.all.rp_filter = 1\n"),
            "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.ip_forward = 1\n"
        );
        assert_eq!(update_config_to_persist(""), "net.ipv4.ip_forward = 1\n");
    }

    #[test]
    fn rewrites_a_value_that_disables_forwarding() {
        let content = "# keep this\nnet.ipv4.ip_forward = 0\n";
        assert_eq!(
            update_config_to_persist(content),
            "# keep this\nnet.ipv4.ip_forward = 1\n"
        );
    }

    #[test]
    fn rewriting_an_already_correct_file_changes_nothing() {
        let content = "net.ipv4.ip_forward = 1\n";
        assert_eq!(update_config_to_persist(content), content);
    }
}
