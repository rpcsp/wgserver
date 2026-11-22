use super::{run_command, write_config_file};
use crate::config::ConfigError;

const SYSCTL_CONFIG: &str = "/etc/sysctl.d/99-wireguard.conf";
const LABEL_KEY_PAIRS: [(&str, &str); 2] = [
    ("IPv4 forwarding", "net.ipv4.ip_forward"),
    ("IPv6 forwarding", "net.ipv6.conf.all.forwarding"),
];

pub fn print_status() {
    for (label, key) in LABEL_KEY_PAIRS {
        match is_enabled(key) {
            Ok(true) => println!("{label} enabled... yes\n"),
            Ok(false) => println!("{label} enabled... no\n"),
            Err(e) => println!("Error: {}", e),
        }
    }
}

pub fn enable() -> Result<(), ConfigError> {
    for (label, key) in LABEL_KEY_PAIRS {
        if !is_enabled(key)? {
            println!("Enabling {label}...");
            run_command("sysctl", &["-w", &format!("{}=1", key)], None)?;
        }
    }
    if !is_persisted() {
        println!("Persisting IP forwarding...");
        persist()?;
    }
    Ok(())
}

/// Check if forwarding is enabled for the given sysctl key.
pub fn is_enabled(key: &str) -> Result<bool, ConfigError> {
    let output = run_command("sysctl", &[key], None)?;
    let enabled = output.contains(&format!("{}=1", key)) || output.contains(&format!("{} = 1", key));
    Ok(enabled)
}

/// Check the persisted value for a key, ignoring comments
fn get_persisted_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if is_comment(line) {
            continue;
        }
        if let Some((k, value)) = line.split_once('=')
            && k.trim() == key
        {
            return value.trim().parse().ok();
        }
    }
    None
}

/// Check if the persistent config already enables every key we manage.
fn is_persisted() -> bool {
    let config = std::fs::read_to_string(SYSCTL_CONFIG).unwrap_or_default();
    LABEL_KEY_PAIRS.iter()
        .all(|(_, key)| get_persisted_value(&config, key) == Some("1".to_string()))
}

/// Set every managed key to 1 in sysctl file content, replacing existing
/// values or appending keys when they are missing.
fn update_config_to_persist(content: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
    for (_, key) in LABEL_KEY_PAIRS {
        let mut found = false;
        for line in &mut lines {
            let trimmed = line.trim();
            if is_comment(trimmed) {
                continue;
            }
            if let Some((k, _)) = trimmed.split_once('=')
                && k.trim() == key
            {
                *line = format!("{key} = 1");
                found = true;
            }
        }
        if !found {
            lines.push(format!("{key} = 1"));
        }
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

    const V4: &str = "net.ipv4.ip_forward";
    const V6: &str = "net.ipv6.conf.all.forwarding";

    #[test]
    fn reads_the_value_set_in_a_sysctl_file() {
        assert_eq!(
            get_persisted_value("net.ipv4.ip_forward = 1\n", V4),
            Some("1".to_string())
        );
        assert_eq!(
            get_persisted_value("net.ipv4.ip_forward=0\n", V4),
            Some("0".to_string())
        );
        assert_eq!(get_persisted_value("", V4), None);
        assert_eq!(
            get_persisted_value("net.ipv6.conf.all.forwarding = 1\n", V6),
            Some("1".to_string())
        );
    }

    #[test]
    fn ignores_comments_and_other_keys() {
        let content = "# net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 1\n";
        assert_eq!(get_persisted_value(content, V4), None);
    }

    #[test]
    fn appends_the_keys_when_they_are_absent() {
        assert_eq!(
            update_config_to_persist("net.ipv4.conf.all.rp_filter = 1\n"),
            "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
        );
        assert_eq!(
            update_config_to_persist(""),
            "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
        );
    }

    #[test]
    fn rewrites_values_that_disable_forwarding() {
        let content = "# keep this\nnet.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\n";
        assert_eq!(
            update_config_to_persist(content),
            "# keep this\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
        );
    }

    #[test]
    fn rewriting_an_already_correct_file_changes_nothing() {
        let content = "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n";
        assert_eq!(update_config_to_persist(content), content);
    }

    #[test]
    fn adds_a_key_that_is_missing_from_a_partially_correct_file() {
        let content = "net.ipv4.ip_forward = 1\n";
        assert_eq!(
            update_config_to_persist(content),
            "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
        );
    }
}
