mod callstack;
mod flat;

use callstack::CallstackProfileMethod;

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
    /// Print file and line info for each entry
    #[clap(long)]
    line_info: bool,
    /// Duration of profile in seconds.
    #[clap(long)]
    duration: u64, // Option<u64> If we could catch ctrl-c we can make this optional
    /// Which core to profile
    #[clap(long, default_value_t = 0)]
    core: usize,
    /// Limit the number of entries to output
    #[clap(long, default_value_t = 25)]
    limit: usize,
    /// Profile Method
    #[clap(subcommand)]
    profile_type: ProfileType,
}

#[derive(clap::Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
enum ProfileType {
    #[clap(name = "flat")]
    #[clap(subcommand)]
    Flat(flat::FlatProfileMethod),
    #[clap(name = "callstack")]
    #[clap(subcommand)]
    Callstack(CallstackProfileMethod),
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

        let file_location = self.run.shared_options.path.as_path();

        if self.flash {
            run_flash_download(
                &mut session,
                file_location,
                &self.run.shared_options.download_options,
                &probe_options,
                loader,
            )?;
        }

        info!("Profiling...");

        match self.profile_type {
            ProfileType::Flat(method) => flat::flat_profile(
                &method,
                &mut session,
                self.line_info,
                self.duration,
                self.core,
                file_location,
                self.limit,
            ),
            ProfileType::Callstack(method) => callstack::callstack_profile(
                &method,
                &mut session,
                self.line_info,
                self.duration,
                self.core,
                file_location,
            ),
        }
    }
}
