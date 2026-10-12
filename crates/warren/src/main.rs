//! The `warren` binary: one executable, three roles, and the client.
//!
//! Each role is a Cargo feature, so a data-path build (`relay` and
//! `connector` only) never links control-plane or console code. Builds with
//! the control plane also carry its operator commands: `warren admin`,
//! which talks to a running control plane over its local admin socket, and
//! `warren policy check`, which compiles a policy directory offline. Builds
//! with the `client` feature carry the command-line client: `warren login`,
//! `warren up`, `warren status`, `warren down` and `warren logout`.

use std::process::ExitCode;

#[cfg(any(feature = "control-plane", feature = "relay", feature = "connector"))]
use clap::Arg;
#[cfg(any(feature = "relay", feature = "connector"))]
use clap::ArgAction;
use clap::{ArgMatches, Command};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "connector")]
mod connector;
#[cfg(any(feature = "relay", feature = "connector"))]
mod node;
#[cfg(feature = "relay")]
mod relay;

#[cfg(not(any(
    feature = "control-plane",
    feature = "relay",
    feature = "connector",
    feature = "client"
)))]
compile_error!("enable at least one role feature: control-plane, relay, connector or client");

/// Arguments every data-path role shares.
#[cfg(any(feature = "relay", feature = "connector"))]
fn node_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("cert")
            .long("cert")
            .value_name("PEM")
            .requires_all(["key", "trust-bundle"])
            .required_unless_present("join-token")
            .help("Infrastructure certificate chain, leaf first"),
    )
    .arg(
        Arg::new("key")
            .long("key")
            .value_name("PEM")
            .requires("cert")
            .help("Private key for the certificate"),
    )
    .arg(
        Arg::new("trust-bundle")
            .long("trust-bundle")
            .value_name("DIR")
            .requires("cert")
            .help("Directory with root-ca.pem, client-ca.pem and infra-ca.pem"),
    )
    .arg(
        Arg::new("join-token")
            .long("join-token")
            .value_name("TOKEN")
            .conflicts_with("cert")
            .requires("state-dir")
            .help("Join the deployment with this single-use token on first start"),
    )
    .arg(
        Arg::new("state-dir")
            .long("state-dir")
            .value_name("DIR")
            .help("Where a joined node keeps its key, certificate and trust bundle"),
    )
    .arg(
        Arg::new("bundle")
            .long("bundle")
            .value_name("JSON")
            .required(true)
            .help(
                "Node bundle: groups, apps, entities, rules and revocations (reloaded on SIGHUP)",
            ),
    )
    .arg(
        Arg::new("metrics")
            .long("metrics")
            .value_name("ADDR")
            .help("Serve Prometheus metrics on /metrics at this address"),
    )
    .arg(
        Arg::new("log-level")
            .long("log-level")
            .value_name("LEVEL")
            .default_value("info")
            .help("error, warn, info, debug or trace (JSON logs on stderr)"),
    )
}

/// The roles compiled into this build, in subcommand order.
#[cfg(test)]
fn roles() -> Vec<&'static str> {
    let mut roles = Vec::new();
    if cfg!(feature = "control-plane") {
        roles.push("control-plane");
    }
    if cfg!(feature = "relay") {
        roles.push("relay");
    }
    if cfg!(feature = "connector") {
        roles.push("connector");
    }
    roles
}

#[cfg(feature = "control-plane")]
fn group_arg() -> Arg {
    Arg::new("group")
        .long("group")
        .action(clap::ArgAction::Append)
        .help("A local group (repeatable)")
}

#[cfg(feature = "control-plane")]
fn admin_command() -> Command {
    let id = |name: &'static str, help: &'static str| Arg::new(name).required(true).help(help);
    let action = |name: &'static str, about: &'static str, arg: Arg| {
        Command::new(name).about(about).arg(arg)
    };
    Command::new("admin")
        .about("Administer a running control plane through its local admin socket")
        .subcommand_required(true)
        .arg(
            Arg::new("socket")
                .long("socket")
                .global(true)
                .default_value("/var/lib/warren/admin.sock")
                .help("The control plane's admin socket"),
        )
        .subcommand(
            Command::new("users")
                .about("Users: the IdP's and built-in accounts")
                .subcommand_required(true)
                .subcommand(Command::new("list").about("List users"))
                .subcommand(
                    Command::new("create")
                        .about("Create a built-in account and print its one-time setup link")
                        .arg(id(
                            "username",
                            "Username: lowercase letters, digits and '-'",
                        ))
                        .arg(Arg::new("email").long("email").help("The user's email"))
                        .arg(
                            Arg::new("name")
                                .long("name")
                                .help("A name to show for the user"),
                        )
                        .arg(group_arg()),
                )
                .subcommand(action(
                    "delete",
                    "Delete a built-in account and cut its connections",
                    id("user", "User ID, username or email"),
                ))
                .subcommand(action(
                    "disable",
                    "Disable a user and cut their connections",
                    id("user", "User ID, email, IdP subject or username"),
                ))
                .subcommand(action(
                    "enable",
                    "Enable a user",
                    id("user", "User ID, email, IdP subject or username"),
                ))
                .subcommand(action(
                    "reset",
                    "Clear a built-in account's password and authenticator, revoke its sessions, and print a new setup link",
                    id("user", "User ID, username or email"),
                ))
                .subcommand(action(
                    "unlock",
                    "Lift a built-in account's lockout after failed sign-ins",
                    id("user", "User ID, username or email"),
                ))
                .subcommand(
                    action(
                        "groups",
                        "Set the local groups a user is in (no --group: none)",
                        id("user", "User ID, email, IdP subject or username"),
                    )
                    .arg(group_arg()),
                )
                .subcommand(action(
                    "sessions",
                    "List a user's sessions",
                    id("user", "User ID, email, IdP subject or username"),
                )),
        )
        .subcommand(
            Command::new("groups")
                .about("warren's own groups, named local:<group> in policy")
                .subcommand_required(true)
                .subcommand(Command::new("list").about("List local groups with their members and invites")),
        )
        .subcommand(
            Command::new("invites")
                .about("Local group memberships waiting for an IdP user's verified email")
                .subcommand_required(true)
                .subcommand(Command::new("list").about("List pending invites"))
                .subcommand(
                    action(
                        "set",
                        "Set the local groups an email is invited to (no --group: none)",
                        id("email", "The verified email the invite binds to"),
                    )
                    .arg(group_arg()),
                ),
        )
        .subcommand(
            Command::new("sessions")
                .about("Sign-in sessions")
                .subcommand_required(true)
                .subcommand(action(
                    "revoke",
                    "Revoke a session and cut its connections",
                    id("session", "Session ID"),
                )),
        )
        .subcommand(
            Command::new("devices")
                .about("Devices")
                .subcommand_required(true)
                .subcommand(Command::new("list").about("List devices"))
                .subcommand(action(
                    "approve",
                    "Approve a pending device",
                    id("device", "Device ID"),
                ))
                .subcommand(action(
                    "enable",
                    "Re-enable a disabled device",
                    id("device", "Device ID"),
                ))
                .subcommand(action(
                    "disable",
                    "Disable a device and cut its connections",
                    id("device", "Device ID"),
                ))
                .subcommand(action(
                    "revoke",
                    "Revoke a device permanently",
                    id("device", "Device ID"),
                )),
        )
        .subcommand(
            Command::new("certificates")
                .about("Issued certificates")
                .subcommand_required(true)
                .subcommand(action(
                    "revoke",
                    "Revoke one certificate",
                    id("serial", "Serial number, hex"),
                )),
        )
        .subcommand(
            Command::new("policy")
                .about("The policy in force")
                .subcommand_required(true)
                .subcommand(
                    Command::new("status").about("Show the policy in force and the last load"),
                )
                .subcommand(Command::new("reload").about("Reload the policy directory")),
        )
        .subcommand(
            Command::new("join-token")
                .about("Join tokens for relays and connectors")
                .subcommand_required(true)
                .subcommand(
                    Command::new("create")
                        .about("Create a single-use join token")
                        .arg(
                            Arg::new("role")
                                .long("role")
                                .required(true)
                                .value_parser(["relay", "connector"]),
                        )
                        .arg(
                            Arg::new("group")
                                .long("group")
                                .help("The connector group, for connectors"),
                        )
                        .arg(
                            Arg::new("name")
                                .long("name")
                                .required(true)
                                .help("The node's name, unique within its role"),
                        )
                        .arg(
                            Arg::new("dns-name")
                                .long("dns-name")
                                .action(clap::ArgAction::Append)
                                .help("A DNS name the relay listens on (repeatable; relays only)"),
                        ),
                ),
        )
        .subcommand(
            Command::new("nodes")
                .about("Relays and connectors")
                .subcommand_required(true)
                .subcommand(Command::new("list").about("List nodes"))
                .subcommand(action(
                    "revoke",
                    "Revoke a node and close its connections",
                    id("node", "Node ID"),
                )),
        )
        .subcommand(
            Command::new("revocation-latency").about("Show the measured commit-to-cut latency"),
        )
        .subcommand(Command::new("deployment").about(
            "Show the trust domain, organization URL and the root fingerprint clients can pin",
        ))
}

fn cli() -> Command {
    let about = if cfg!(any(
        feature = "control-plane",
        feature = "relay",
        feature = "connector"
    )) {
        "Zero-trust private access: control plane, relay, connector and client in one binary"
    } else {
        "Zero-trust private access to your organization's internal apps"
    };
    let mut cmd = Command::new("warren")
        .version(env!("CARGO_PKG_VERSION"))
        .about(about)
        .subcommand_required(true)
        .arg_required_else_help(true);
    #[cfg(feature = "control-plane")]
    {
        cmd = cmd.subcommand(
            Command::new("control-plane")
                .about(warren_control::ABOUT)
                .arg(
                    Arg::new("config")
                        .long("config")
                        .default_value("/etc/warren/control-plane.yaml")
                        .help("The control plane's configuration file"),
                ),
        );
    }
    #[cfg(feature = "relay")]
    {
        let relay = Command::new("relay")
            .about(warren_relay::ABOUT)
            .arg(
                Arg::new("listen")
                    .long("listen")
                    .value_name("ADDR")
                    .default_value("[::]:443")
                    .help("UDP address for QUIC"),
            )
            .arg(
                Arg::new("listen-tcp")
                    .long("listen-tcp")
                    .value_name("ADDR")
                    .help("TCP address for the HTTP/2 fallback [default: the QUIC address]"),
            )
            .arg(
                Arg::new("no-tcp")
                    .long("no-tcp")
                    .action(ArgAction::SetTrue)
                    .help("Do not serve the HTTP/2 fallback"),
            )
            .arg(
                Arg::new("peer-prefix")
                    .long("peer-prefix")
                    .value_name("IPV6")
                    .help("IPv6 /64 for virtual peer addresses [default: random ULA]"),
            )
            .arg(
                Arg::new("max-splices-per-client")
                    .long("max-splices-per-client")
                    .value_name("N")
                    .default_value("64")
                    .value_parser(clap::value_parser!(usize))
                    .help("Concurrent tunnels allowed per client device"),
            );
        cmd = cmd.subcommand(node_args(relay));
    }
    #[cfg(feature = "connector")]
    {
        let connector = Command::new("connector")
            .about(warren_connector::ABOUT)
            .arg(
                Arg::new("group")
                    .long("group")
                    .value_name("NAME")
                    .required(true)
                    .help("Connector group (must match the certificate)"),
            )
            .arg(
                Arg::new("relay")
                    .long("relay")
                    .value_name("NAME[@HOST:PORT]")
                    .required(true)
                    .action(ArgAction::Append)
                    .help("A relay to attach to; repeat for each relay in the relay set"),
            )
            .arg(
                Arg::new("transport")
                    .long("transport")
                    .value_name("MODE")
                    .default_value("auto")
                    .value_parser(["auto", "quic", "h2"])
                    .help("Carrier for attachments"),
            )
            .arg(
                Arg::new("audit")
                    .long("audit")
                    .value_name("PATH")
                    .help("Append audit records here [default: stdout]"),
            )
            .arg(
                Arg::new("tun-name")
                    .long("tun-name")
                    .value_name("NAME")
                    .default_value("warren0")
                    .help("TUN interface for kernel forwarding"),
            )
            .arg(
                Arg::new("nat")
                    .long("nat")
                    .value_name("MODE")
                    .default_value("masquerade")
                    .value_parser(["masquerade", "none"])
                    .help("Install warren's masquerade table, or leave NAT to the operator"),
            )
            .arg(
                Arg::new("device-pool")
                    .long("device-pool")
                    .value_name("CIDR")
                    .action(ArgAction::Append)
                    .help("Device address pools [default: the deployment defaults]"),
            )
            .arg(
                Arg::new("synthetic-pool")
                    .long("synthetic-pool")
                    .value_name("CIDR")
                    .action(ArgAction::Append)
                    .help("Synthetic address pools for names [default: the deployment defaults]"),
            )
            .arg(
                Arg::new("tunnel-mtu")
                    .long("tunnel-mtu")
                    .value_name("BYTES")
                    .default_value("1280")
                    .value_parser(clap::value_parser!(u16))
                    .help("Tunnel MTU; never below 1280"),
            )
            .arg(
                Arg::new("drain-timeout")
                    .long("drain-timeout")
                    .value_name("SECONDS")
                    .default_value("300")
                    .value_parser(clap::value_parser!(u64))
                    .help("How long a stopping connector keeps existing sessions"),
            );
        cmd = cmd.subcommand(node_args(connector));
    }
    #[cfg(feature = "control-plane")]
    {
        cmd = cmd.subcommand(admin_command()).subcommand(
            Command::new("policy")
                .about("Work with a policy directory offline")
                .subcommand_required(true)
                .subcommand(
                    Command::new("check")
                        .about("Compile a policy directory to Cedar and report every problem")
                        .arg(Arg::new("dir").required(true).help("The policy directory")),
                ),
        );
    }
    #[cfg(feature = "client")]
    {
        cmd = cmd.subcommands(client::commands());
    }
    cmd
}

fn run(name: &str, matches: &ArgMatches) -> Result<(), String> {
    match name {
        #[cfg(feature = "relay")]
        "relay" => relay::run(matches),
        #[cfg(feature = "connector")]
        "connector" => connector::run(matches),
        other => {
            let _ = matches;
            Err(format!("warren {other}: not implemented in this build yet"))
        }
    }
}

/// Identifiers go into admin URL paths as they are, so only characters that
/// need no escaping are accepted.
#[cfg(feature = "control-plane")]
fn path_segment(value: &str) -> Result<&str, String> {
    if !value.is_empty()
        && value.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'@' | b'+' | b':')
        })
    {
        Ok(value)
    } else {
        Err(format!(
            "{value:?} has characters an identifier cannot have here; use the ID from the list command"
        ))
    }
}

/// The admin request for a parsed `warren admin` command line.
#[cfg(feature = "control-plane")]
fn admin_request(m: &ArgMatches) -> Result<(&'static str, String, Option<String>), String> {
    let (group, sub) = m.subcommand().ok_or("missing command")?;
    let arg = |name: &str| -> Result<&str, String> {
        sub.subcommand()
            .and_then(|(_, a)| a.get_one::<String>(name))
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}"))
            .and_then(path_segment)
    };
    let action = sub.subcommand_name().unwrap_or("");
    let groups = || -> Vec<String> {
        sub.subcommand()
            .and_then(|(_, a)| a.get_many::<String>("group"))
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    };
    let text = |name: &str| -> Option<String> {
        sub.subcommand()
            .and_then(|(_, a)| a.get_one::<String>(name))
            .cloned()
    };
    Ok(match (group, action) {
        ("users", "list") => ("GET", "/v1/admin/users".into(), None),
        ("users", "create") => {
            let mut body = serde_json::Map::new();
            body.insert("username".into(), arg("username")?.into());
            if let Some(email) = text("email") {
                body.insert("email".into(), email.into());
            }
            if let Some(name) = text("name") {
                body.insert("display_name".into(), name.into());
            }
            body.insert("groups".into(), groups().into());
            (
                "POST",
                "/v1/admin/users".into(),
                Some(serde_json::Value::Object(body).to_string()),
            )
        }
        ("users", "delete") => ("DELETE", format!("/v1/admin/users/{}", arg("user")?), None),
        ("users", "groups") => (
            "PUT",
            format!("/v1/admin/users/{}/groups", arg("user")?),
            Some(serde_json::json!({ "groups": groups() }).to_string()),
        ),
        ("users", "sessions") => (
            "GET",
            format!("/v1/admin/users/{}/sessions", arg("user")?),
            None,
        ),
        ("users", a) => (
            "POST",
            format!("/v1/admin/users/{}/{a}", arg("user")?),
            None,
        ),
        ("groups", "list") => ("GET", "/v1/admin/groups".into(), None),
        ("invites", "list") => ("GET", "/v1/admin/invites".into(), None),
        ("invites", "set") => (
            "PUT",
            format!("/v1/admin/invites/{}", arg("email")?),
            Some(serde_json::json!({ "groups": groups() }).to_string()),
        ),
        ("sessions", "revoke") => (
            "POST",
            format!("/v1/admin/sessions/{}/revoke", arg("session")?),
            None,
        ),
        ("devices", "list") => ("GET", "/v1/admin/devices".into(), None),
        ("devices", a) => (
            "POST",
            format!("/v1/admin/devices/{}/{a}", arg("device")?),
            None,
        ),
        ("certificates", "revoke") => (
            "POST",
            format!("/v1/admin/certificates/{}/revoke", arg("serial")?),
            None,
        ),
        ("policy", "status") => ("GET", "/v1/admin/policy".into(), None),
        ("policy", "reload") => ("POST", "/v1/admin/policy/reload".into(), None),
        ("join-token", "create") => {
            let a = sub
                .subcommand_matches("create")
                .ok_or("missing arguments")?;
            let role = a.get_one::<String>("role").ok_or("missing --role")?;
            let mut body = format!(r#"{{"role":"{role}""#);
            if let Some(g) = a.get_one::<String>("group") {
                body.push_str(&format!(r#","group":"{}""#, path_segment(g)?));
            }
            let name = a.get_one::<String>("name").ok_or("missing --name")?;
            body.push_str(&format!(r#","name":"{}""#, path_segment(name)?));
            let dns = a
                .get_many::<String>("dns-name")
                .into_iter()
                .flatten()
                .map(|d| path_segment(d).map(|d| format!(r#""{d}""#)))
                .collect::<Result<Vec<_>, _>>()?;
            if !dns.is_empty() {
                body.push_str(&format!(r#","dns_names":[{}]"#, dns.join(",")));
            }
            body.push('}');
            ("POST", "/v1/admin/join-tokens".into(), Some(body))
        }
        ("nodes", "list") => ("GET", "/v1/admin/nodes".into(), None),
        ("nodes", "revoke") => (
            "POST",
            format!("/v1/admin/nodes/{}/revoke", arg("node")?),
            None,
        ),
        ("revocation-latency", _) => ("GET", "/v1/admin/revocation-latency".into(), None),
        ("deployment", _) => ("GET", "/v1/admin/deployment".into(), None),
        _ => return Err("unknown admin command".into()),
    })
}

#[cfg(feature = "control-plane")]
fn control_plane_commands(name: &str, m: &ArgMatches) -> Option<ExitCode> {
    match name {
        "control-plane" => {
            let config = m
                .get_one::<String>("config")
                .map(String::as_str)
                .unwrap_or_default();
            Some(match warren_control::run(std::path::Path::new(config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("warren control-plane: {e}");
                    ExitCode::FAILURE
                }
            })
        }
        "admin" => {
            let socket = m
                .get_one::<String>("socket")
                .map(String::as_str)
                .unwrap_or_default();
            let (method, path, body) = match admin_request(m) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warren admin: {e}");
                    return Some(ExitCode::FAILURE);
                }
            };
            Some(
                match warren_control::admin_request(
                    std::path::Path::new(socket),
                    method,
                    &path,
                    body,
                ) {
                    Ok((status, text)) => {
                        println!("{text}");
                        if (200..300).contains(&status) {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    Err(e) => {
                        eprintln!("warren admin: {e}");
                        ExitCode::FAILURE
                    }
                },
            )
        }
        "policy" => {
            let dir = m
                .subcommand_matches("check")
                .and_then(|c| c.get_one::<String>("dir"))
                .map(String::as_str)
                .unwrap_or_default();
            Some(
                match warren_control::check_policy(std::path::Path::new(dir), &[]) {
                    Ok((cedar, warnings)) => {
                        for w in warnings {
                            eprintln!("{w}");
                        }
                        print!("{cedar}");
                        ExitCode::SUCCESS
                    }
                    Err(errors) => {
                        for e in errors {
                            eprintln!("{e}");
                        }
                        ExitCode::FAILURE
                    }
                },
            )
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let (name, sub) = matches.subcommand().expect("subcommand_required");
    #[cfg(feature = "control-plane")]
    if let Some(code) = control_plane_commands(name, sub) {
        return code;
    }
    #[cfg(feature = "client")]
    if let Some(code) = client::run(name, sub) {
        return code;
    }
    match run(name, sub) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warren {name}: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::{cli, roles};

    #[test]
    fn cli_is_well_formed() {
        cli().debug_assert();
    }

    #[test]
    fn compiled_roles_lead_the_subcommands() {
        let cmd = cli();
        let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        let roles = roles();
        assert_eq!(&names[..roles.len()], roles.as_slice());
        // Operator commands exist exactly when the control plane is built,
        // and client commands exactly when the client is.
        #[cfg_attr(not(feature = "client"), allow(unused_mut))]
        let mut tools: Vec<&str> = names[roles.len()..].to_vec();
        #[cfg(feature = "client")]
        {
            let client = tools.split_off(tools.len() - crate::client::NAMES.len());
            assert_eq!(client, crate::client::NAMES);
        }
        if cfg!(feature = "control-plane") {
            assert_eq!(tools, ["admin", "policy"]);
        } else {
            assert!(tools.is_empty());
        }
    }

    #[test]
    fn version_flag_reports_the_package_version() {
        let err = cli()
            .try_get_matches_from(["warren", "--version"])
            .expect_err("--version exits early");
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn every_role_answers_help() {
        for role in roles() {
            let err = cli()
                .try_get_matches_from(["warren", role, "--help"])
                .expect_err("--help exits early");
            assert_eq!(err.kind(), ErrorKind::DisplayHelp, "role {role}");
        }
    }

    #[cfg(feature = "connector")]
    #[test]
    fn connector_requires_a_group_and_relays() {
        let err = cli()
            .try_get_matches_from(["warren", "connector", "--cert", "c", "--key", "k"])
            .expect_err("missing arguments");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn admin_commands_map_to_the_admin_api() {
        let cases: &[(&[&str], &str, &str, Option<&str>)] = &[
            (&["users", "list"], "GET", "/v1/admin/users", None),
            (
                &["users", "disable", "ada@example.com"],
                "POST",
                "/v1/admin/users/ada@example.com/disable",
                None,
            ),
            (
                &["devices", "approve", "d-1"],
                "POST",
                "/v1/admin/devices/d-1/approve",
                None,
            ),
            (
                &["policy", "reload"],
                "POST",
                "/v1/admin/policy/reload",
                None,
            ),
            (
                &[
                    "join-token",
                    "create",
                    "--role",
                    "connector",
                    "--group",
                    "homelab",
                    "--name",
                    "lab-1",
                ],
                "POST",
                "/v1/admin/join-tokens",
                Some(r#"{"role":"connector","group":"homelab","name":"lab-1"}"#),
            ),
            (
                &[
                    "join-token",
                    "create",
                    "--role",
                    "relay",
                    "--name",
                    "relay-1",
                    "--dns-name",
                    "relay1.example.com",
                    "--dns-name",
                    "relay1.example.net",
                ],
                "POST",
                "/v1/admin/join-tokens",
                Some(
                    r#"{"role":"relay","name":"relay-1","dns_names":["relay1.example.com","relay1.example.net"]}"#,
                ),
            ),
            (
                &["revocation-latency"],
                "GET",
                "/v1/admin/revocation-latency",
                None,
            ),
            (&["deployment"], "GET", "/v1/admin/deployment", None),
            (
                &[
                    "users",
                    "create",
                    "ada",
                    "--email",
                    "ada@example.com",
                    "--name",
                    "Ada \"the Countess\" Lovelace",
                    "--group",
                    "ops",
                    "--group",
                    "admins",
                ],
                "POST",
                "/v1/admin/users",
                Some(
                    r#"{"username":"ada","email":"ada@example.com","display_name":"Ada \"the Countess\" Lovelace","groups":["ops","admins"]}"#,
                ),
            ),
            (
                &["users", "delete", "local:ada"],
                "DELETE",
                "/v1/admin/users/local:ada",
                None,
            ),
            (
                &["users", "reset", "ada"],
                "POST",
                "/v1/admin/users/ada/reset",
                None,
            ),
            (
                &["users", "unlock", "ada"],
                "POST",
                "/v1/admin/users/ada/unlock",
                None,
            ),
            (
                &["users", "groups", "ada", "--group", "ops"],
                "PUT",
                "/v1/admin/users/ada/groups",
                Some(r#"{"groups":["ops"]}"#),
            ),
            (
                &["users", "groups", "ada"],
                "PUT",
                "/v1/admin/users/ada/groups",
                Some(r#"{"groups":[]}"#),
            ),
            (&["groups", "list"], "GET", "/v1/admin/groups", None),
            (&["invites", "list"], "GET", "/v1/admin/invites", None),
            (
                &["invites", "set", "bob@example.com", "--group", "ops"],
                "PUT",
                "/v1/admin/invites/bob@example.com",
                Some(r#"{"groups":["ops"]}"#),
            ),
        ];
        for (args, method, path, body) in cases {
            let argv: Vec<&str> = ["warren", "admin"]
                .iter()
                .chain(args.iter())
                .copied()
                .collect();
            let m = cli().try_get_matches_from(argv).unwrap();
            let (_, admin) = m.subcommand().unwrap();
            let (got_method, got_path, got_body) = super::admin_request(admin).unwrap();
            assert_eq!(
                (got_method, got_path.as_str(), got_body.as_deref()),
                (*method, *path, *body)
            );
        }
        let m = cli()
            .try_get_matches_from(["warren", "admin", "users", "disable", "a/b"])
            .unwrap();
        assert!(super::admin_request(m.subcommand().unwrap().1).is_err());
    }
}
