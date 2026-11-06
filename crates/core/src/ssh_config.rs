//! Parser for OpenSSH client configuration files (`~/.ssh/config`).
//!
//! Safely extracts host configurations (`HostName`, `User`, `Port`, `IdentityFile`,
//! `ProxyJump`) without executing arbitrary shell commands. Potentially dangerous
//! options like `ProxyCommand` are safely ignored with an advisory warning.

use crate::error::CoreError;
use easyssh_proto::{AuthMethod, HostConfig, HostId, KeyHandle};
use std::collections::HashMap;

/// Parsed raw properties for an SSH configuration section.
#[derive(Debug, Default, Clone)]
struct ConfigSection {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    ignored_proxy_commands: Vec<String>,
}

/// Parses OpenSSH configuration content into a list of `HostConfig` structs.
pub fn parse_ssh_config(content: &str) -> Result<Vec<HostConfig>, CoreError> {
    let mut global_defaults = ConfigSection::default();
    let mut sections: Vec<(String, ConfigSection)> = Vec::new();
    let mut current_hosts: Option<Vec<String>> = None;
    let mut current_section = ConfigSection::default();

    for (line_num, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split key and value (separated by whitespace or '=')
        let (key, value) = match split_directive(trimmed) {
            Some(pair) => pair,
            None => {
                tracing::debug!("Skipping malformed line {}: '{}'", line_num + 1, trimmed);
                continue;
            }
        };

        if key.eq_ignore_ascii_case("Host") {
            // Save previous section if present
            if let Some(hosts) = current_hosts.take() {
                for h in hosts {
                    if h == "*" {
                        merge_defaults(&mut global_defaults, &current_section);
                    } else {
                        sections.push((h, current_section.clone()));
                    }
                }
            }
            current_section = ConfigSection::default();
            current_hosts = Some(
                value
                    .split_whitespace()
                    .map(|s| s.trim_matches('"').to_string())
                    .collect(),
            );
            continue;
        }

        let clean_value = value.trim_matches('"').to_string();

        if key.eq_ignore_ascii_case("HostName") {
            current_section.hostname = Some(clean_value);
        } else if key.eq_ignore_ascii_case("User") {
            current_section.user = Some(clean_value);
        } else if key.eq_ignore_ascii_case("Port") {
            if let Ok(p) = clean_value.parse::<u16>() {
                current_section.port = Some(p);
            }
        } else if key.eq_ignore_ascii_case("IdentityFile") {
            current_section.identity_file = Some(clean_value);
        } else if key.eq_ignore_ascii_case("ProxyJump") {
            current_section.proxy_jump = Some(clean_value);
        } else if key.eq_ignore_ascii_case("ProxyCommand") {
            tracing::warn!(
                "Safely ignoring potentially unsafe ProxyCommand directive on line {}: '{}'",
                line_num + 1,
                clean_value
            );
            current_section.ignored_proxy_commands.push(clean_value);
        }
    }

    // Flush last block
    if let Some(hosts) = current_hosts {
        for h in hosts {
            if h == "*" {
                merge_defaults(&mut global_defaults, &current_section);
            } else {
                sections.push((h, current_section.clone()));
            }
        }
    }

    let mut result = Vec::new();
    let mut deduplication_map: HashMap<String, usize> = HashMap::new();

    for (alias, section) in sections {
        // Skip purely wildcard catch-all patterns as standalone hosts
        if alias.contains('*') || alias.contains('?') {
            continue;
        }

        let hostname = section
            .hostname
            .or_else(|| global_defaults.hostname.clone())
            .unwrap_or_else(|| alias.clone());

        let user = section
            .user
            .or_else(|| global_defaults.user.clone())
            .unwrap_or_else(|| "root".to_string());

        let port = section.port.or(global_defaults.port).unwrap_or(22);

        let identity_file = section
            .identity_file
            .or_else(|| global_defaults.identity_file.clone());

        let proxy_jump = section
            .proxy_jump
            .or_else(|| global_defaults.proxy_jump.clone());

        let auth = match identity_file {
            Some(path) => AuthMethod::PrivateKey {
                key_handle: KeyHandle::new(path),
            },
            None => AuthMethod::Password,
        };

        let host_entry = HostConfig {
            id: HostId::new(format!("ssh-config-{}", alias)),
            name: alias.clone(),
            hostname,
            port,
            username: user,
            auth,
            jump_host: proxy_jump.map(HostId::new),
            tags: vec!["ssh-config".to_string()],
        };

        if let Some(&idx) = deduplication_map.get(&alias) {
            result[idx] = host_entry;
        } else {
            deduplication_map.insert(alias, result.len());
            result.push(host_entry);
        }
    }

    Ok(result)
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    let sep_idx = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..sep_idx].trim();
    let rest = line[sep_idx..].trim_start();
    let value = rest.strip_prefix('=').unwrap_or(rest).trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

fn merge_defaults(target: &mut ConfigSection, source: &ConfigSection) {
    if target.hostname.is_none() && source.hostname.is_some() {
        target.hostname = source.hostname.clone();
    }
    if target.user.is_none() && source.user.is_some() {
        target.user = source.user.clone();
    }
    if target.port.is_none() && source.port.is_some() {
        target.port = source.port;
    }
    if target.identity_file.is_none() && source.identity_file.is_some() {
        target.identity_file = source.identity_file.clone();
    }
    if target.proxy_jump.is_none() && source.proxy_jump.is_some() {
        target.proxy_jump = source.proxy_jump.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_config_basic() {
        let config = r#"
# Global options
Host *
    User devops
    Port 22

Host web-prod
    HostName 198.51.100.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/prod_key

Host bastion
    HostName bastion.example.com
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
"#;

        let hosts = parse_ssh_config(config).unwrap();
        assert_eq!(hosts.len(), 2);

        let web = hosts.iter().find(|h| h.name == "web-prod").unwrap();
        assert_eq!(web.hostname, "198.51.100.10");
        assert_eq!(web.username, "admin");
        assert_eq!(web.port, 2222);
        assert_eq!(
            web.auth,
            AuthMethod::PrivateKey {
                key_handle: KeyHandle::new("~/.ssh/prod_key")
            }
        );

        let bastion = hosts.iter().find(|h| h.name == "bastion").unwrap();
        assert_eq!(bastion.hostname, "bastion.example.com");
        // Inherited default user devops
        assert_eq!(bastion.username, "devops");
        assert_eq!(bastion.port, 22);
        // ProxyCommand was safely ignored
    }

    #[test]
    fn test_parse_ssh_config_with_equals() {
        let config = r#"
Host db=prod
HostName=db.internal
User=postgres
Port=5432
"#;
        let hosts = parse_ssh_config(config).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "db=prod");
        assert_eq!(hosts[0].hostname, "db.internal");
        assert_eq!(hosts[0].username, "postgres");
        assert_eq!(hosts[0].port, 5432);
    }
}
