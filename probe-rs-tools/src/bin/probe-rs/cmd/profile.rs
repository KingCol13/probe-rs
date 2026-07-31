mod callstack;
mod flat;

use probe_rs::config::Registry;
use probe_rs::probe::list::Lister;

use crate::util::{common_options::BinaryDownloadOptions, flash::{build_loader, run_flash_download}};
use tracing::info;

#[derive(clap::Parser)]
pub(crate) struct ProfileCmd {
    #[clap(flatten)]
    run: super::run::Cmd,
    /// Flash the ELF before profiling
    #[clap(long)]
    flash: bool,
    /// Duration of profile in seconds.
    #[clap(long)]
    duration: u64, // Option<u64> If we could catch ctrl-c we can make this optional
    /// Profiling type
    #[clap(subcommand)]
    profile_type: ProfileType,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq)]
#[non_exhaustive]
enum ProfileType {
    /// Faster flat profiling that only records currently executing function
    #[clap(name = "flat")]
    Flat(flat::FlatProfileArgs),
    /// Slower callstack profiling that records the executing function and all callers
    #[clap(name = "callstack")]
    Callstack(callstack::CallstackProfileArgs),
}

impl ProfileCmd {
    pub fn run(self, registry: &mut Registry, lister: &Lister) -> anyhow::Result<()> {
        let (mut session, probe_options) =
            self.run.probe_options.simple_attach(registry, lister)?;

        let loader = build_loader(&mut session, &self.run.path, self.run.format_options, None)?;

        let file_location = self.run.path.as_path();

        if self.flash {
            // We want to allow resetting without flashing so do reset later
            let download_options_no_reset = BinaryDownloadOptions {
                reset: false,
                ..self.run.download_options
            };
            run_flash_download(
                &mut session,
                file_location,
                &download_options_no_reset,
                &probe_options,
                loader,
            )?;
        }

        if self.run.download_options.reset {
            for (core_idx, _) in session.list_cores() {
                let mut core = match session.core(core_idx) {
                    Ok(core) => core,
                    Err(probe_rs::Error::CoreDisabled(_)) => continue,
                    Err(e) => return Err(e.into()),
                };
                core.reset()?;
            }
        }

        info!("Profiling...");

        match self.profile_type {
            ProfileType::Flat(flat_args) => flat::flat_profile(
                &flat_args.method,
                &mut session,
                flat_args.line_info,
                self.duration,
                flat_args.core,
                file_location,
                flat_args.limit,
            ),
            ProfileType::Callstack(callstack_args) => callstack::callstack_profile(
                &mut session,
                self.duration,
                file_location,
                &callstack_args,
            ),
        }
    }
}
