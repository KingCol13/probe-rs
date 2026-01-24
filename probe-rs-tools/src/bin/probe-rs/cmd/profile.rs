mod callstack;
mod flat;

use probe_rs::config::Registry;
use probe_rs::probe::list::Lister;

use crate::util::flash::{build_loader, run_flash_download};
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
    /// Profile Method
    #[clap(subcommand)]
    profile_type: ProfileType,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
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
        let (mut session, probe_options) = self
            .run
            .shared_options
            .probe_options
            .simple_attach(registry, lister)?;

        let loader = build_loader(
            &mut session,
            &self.run.shared_options.path,
            self.run.shared_options.format_options,
            None,
        )?;

        let executable_location = self.run.shared_options.path.as_path();

        if self.flash {
            run_flash_download(
                &mut session,
                executable_location,
                &self.run.shared_options.download_options,
                &probe_options,
                loader,
            )?;
        }

        info!("Profiling...");

        match self.profile_type {
            ProfileType::Flat(flat_args) => flat::flat_profile(
                &flat_args.method,
                &mut session,
                flat_args.line_info,
                self.duration,
                flat_args.core,
                executable_location,
                flat_args.limit,
            ),
            ProfileType::Callstack(callstack_args) => callstack::callstack_profile(
                &callstack_args.method,
                &mut session,
                self.duration,
                callstack_args.rate,
                &callstack_args.cores,
                executable_location,
            ),
        }
    }
}
