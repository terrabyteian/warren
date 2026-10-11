//! The `warren` binary: one executable, three roles.
//!
//! Each role is a Cargo feature, so a data-path build (`relay` and
//! `connector` only) never links control-plane or console code. At the design
//! stage the role subcommands answer `--help` and nothing else.

use std::process::ExitCode;

use clap::Command;

#[cfg(not(any(feature = "control-plane", feature = "relay", feature = "connector")))]
compile_error!("enable at least one role feature: control-plane, relay or connector");

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
        cmd = cmd.subcommand(Command::new("relay").about(warren_relay::ABOUT));
    }
    #[cfg(feature = "connector")]
    {
        cmd = cmd.subcommand(Command::new("connector").about(warren_connector::ABOUT));
    }
    cmd
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let role = matches.subcommand_name().unwrap_or_default();
    eprintln!(
        "warren {role}: not implemented yet; warren is at the design stage (see docs/design.md)"
    );
    ExitCode::FAILURE
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
}
