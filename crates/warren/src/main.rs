//! The `warren` binary: one executable, three roles.
//!
//! Each role is a Cargo feature, so a data-path build (`relay` and
//! `connector` only) never links control-plane or console code.

use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};

#[cfg(feature = "connector")]
mod connector;
#[cfg(any(feature = "relay", feature = "connector"))]
mod node;
#[cfg(feature = "relay")]
mod relay;

#[cfg(not(any(feature = "control-plane", feature = "relay", feature = "connector")))]
compile_error!("enable at least one role feature: control-plane, relay or connector");

/// Arguments every data-path role shares.
#[cfg(any(feature = "relay", feature = "connector"))]
fn node_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("cert")
            .long("cert")
            .value_name("PEM")
            .required(true)
            .help("Infrastructure certificate chain, leaf first"),
    )
    .arg(
        Arg::new("key")
            .long("key")
            .value_name("PEM")
            .required(true)
            .help("Private key for the certificate"),
    )
    .arg(
        Arg::new("trust-bundle")
            .long("trust-bundle")
            .value_name("DIR")
            .required(true)
            .help("Directory with root-ca.pem, client-ca.pem and infra-ca.pem"),
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

fn cli() -> Command {
    let mut cmd = Command::new("warren")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Zero-trust private access: control plane, relay and connector in one binary")
        .subcommand_required(true)
        .arg_required_else_help(true);
    #[cfg(feature = "control-plane")]
    {
        cmd = cmd.subcommand(Command::new("control-plane").about(warren_control::ABOUT));
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

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let (name, sub) = matches.subcommand().expect("subcommand_required");
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

    use super::cli;

    #[test]
    fn cli_is_well_formed() {
        cli().debug_assert();
    }

    #[test]
    fn compiled_roles_are_the_subcommands() {
        let mut expected = Vec::new();
        if cfg!(feature = "control-plane") {
            expected.push("control-plane");
        }
        if cfg!(feature = "relay") {
            expected.push("relay");
        }
        if cfg!(feature = "connector") {
            expected.push("connector");
        }
        let cmd = cli();
        let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert_eq!(names, expected);
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
        for role in cli().get_subcommands().map(|c| c.get_name().to_owned()) {
            let err = cli()
                .try_get_matches_from(["warren", role.as_str(), "--help"])
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
}
