use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use probe_rs_debug::DebugInfo;
use probe_rs_debug::DebugRegisters;

use fxprof_processed_profile as fxprofpp;
use object::Object;
use object::ObjectSegment;
use probe_rs::Session;
use samply_debugid::code_id_for_object;
use samply_debugid::debug_id_for_object;

#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallstackProfileArgs {
    #[clap(subcommand)]
    pub(crate) method: CallstackProfileMethod,
    /// Target interval between samples in ns
    #[clap(long, default_value_t = 500_000_000)]
    pub(crate) interval_ns: u64,
    /// Comma separated list of cores to profile, numbered from 0. If empty all cores will be
    /// profiled
    #[clap(long, value_delimiter = ',')]
    pub(crate) cores: Vec<usize>,
    /// Output format
    #[clap(long, value_enum, default_value_t = OutputFormat::FirefoxProfiler)]
    pub(crate) output_format: OutputFormat,
}

#[derive(clap::Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallstackProfileMethod {
    /// Naive dwarf debug, halt -> walk callstack using debug info -> resume
    NaiveDwarf,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    FirefoxProfiler,
}

impl std::fmt::Display for CallstackProfileMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = format!("{self:?}");
        write!(f, "{}", s.to_lowercase())
    }
}

#[derive(Clone, Copy, Debug)]
struct StackFrameInfo {
    pc: u64,
}

impl From<&StackFrameInfo> for fxprofpp::FrameInfo {
    fn from(value: &StackFrameInfo) -> Self {
        fxprofpp::FrameInfo {
            frame: fxprofpp::Frame::InstructionPointer(value.pc),
            category_pair: fxprofpp::CategoryHandle::OTHER.into(),
            flags: fxprofpp::FrameFlags::empty(),
        }
    }
}

#[derive(Clone, Debug)]
struct CallstackSample {
    // element 0 is root node
    // element 1 is first callee, etc
    callstack: Vec<StackFrameInfo>,
    // time since profiling started
    time: Duration,
}

/// Get virtual memory address of the first segment in binary - i.e. mapping created by first ELF
/// `LOAD` command.
/// Returns None if there are no segments.
fn get_base_address(elf: &object::File) -> Option<u64> {
    elf.segments().map(|s| s.address()).min()
}

fn make_fx_profile(
    callstacks: &Vec<Vec<CallstackSample>>,
    start_time: &SystemTime,
    sampling_interval: &Duration,
    binary_path: &std::path::Path,
) -> fxprofpp::Profile {
    let start_timestamp = (*start_time).into();

    // TODO: propagate errors
    let binary_name: String = binary_path
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let abs_binary_path: String = binary_path
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let mut profile = fxprofpp::Profile::new(
        // TODO: give this a better name
        &binary_name,
        start_timestamp,
        (*sampling_interval).into(),
    );

    let process = profile.add_process(
        "process",
        0,
        fxprofpp::Timestamp::from_nanos_since_reference(0),
    );

    let elf_bytes = std::fs::read(binary_path).unwrap();
    let elf = object::File::parse(&*elf_bytes).unwrap();
    let debug_id = debug_id_for_object(&elf).unwrap();
    let code_id = code_id_for_object(&elf);

    let library_info = fxprofpp::LibraryInfo {
        name: binary_name.clone(),
        debug_name: binary_name.clone(),
        path: abs_binary_path.clone(),
        debug_path: abs_binary_path.clone(),
        debug_id,
        code_id: code_id.map(|id| id.to_string()),
        arch: None,
        symbol_table: None,
    };
    let library = profile.add_lib(library_info);

    let start_avma = get_base_address(&elf).unwrap();
    profile.add_lib_mapping(process, library, start_avma, u64::MAX, 0);

    for (i_core, core_callstacks) in callstacks.iter().enumerate() {
        //TODO: check whether is_main should be set or not
        let thread = profile.add_thread(
            process,
            i_core as u32,
            fxprofpp::Timestamp::from_nanos_since_reference(0),
            true,
        );
        for sample in core_callstacks {
            let stack_frames = sample.callstack.iter().map(|frame| frame.into());
            let stack = profile.intern_stack_frames(thread, stack_frames);
            profile.add_sample(
                thread,
                fxprofpp::Timestamp::from_nanos_since_reference(sample.time.as_nanos() as u64),
                stack,
                fxprofpp::CpuDelta::ZERO,
                1,
            );
        }
    }

    profile
}

fn save_fx_profile(
    profile: &fxprofpp::Profile,
    output_dir: &std::path::PathBuf,
    profile_name: &str,
) -> std::io::Result<()> {
    let output_path = output_dir.join(profile_name).with_extension("json.gz");
    let output_file = std::fs::File::create(output_path)?;

    const GZIP_COMPRESSION_LEVEL: u32 = 2;

    let writer = std::io::BufWriter::new(output_file);
    let builder = flate2::GzBuilder::new().filename(profile_name.as_bytes());
    let gz = builder.write(writer, flate2::Compression::new(GZIP_COMPRESSION_LEVEL));
    let gz = std::io::BufWriter::new(gz);
    serde_json::to_writer(gz, &profile)?;
    Ok(())
}

pub(super) fn callstack_profile(
    method: &CallstackProfileMethod,
    session: &mut Session,
    duration: u64,
    interval_ns: u64,
    cores: &[usize],
    executable_location: &Path,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let start_sys_time = std::time::SystemTime::now();
    let mut samples: Vec<CallstackSample> = Vec::new();
    let duration = Duration::from_secs(duration);
    let debug_info = DebugInfo::from_file(executable_location)?;

    let sampling_interval = Duration::from_nanos(interval_ns);

    // TODO: make able to sample multiple cores
    let core_idx = *cores.first().unwrap();

    match method {
        CallstackProfileMethod::NaiveDwarf => {
            let mut core = session.core(core_idx)?;
            //TODO: make resetting optional
            // core.reset()?;

            loop {
                core.halt(Duration::from_millis(10))?;
                let debug_registers = DebugRegisters::from_core(&mut core);
                let exception_handler =
                    probe_rs_debug::exception_handler_for_core(core.core_type());
                let instruction_set = core.instruction_set()?;
                let stack_frames = debug_info.unwind(
                    &mut core,
                    debug_registers,
                    exception_handler.as_ref(),
                    Some(instruction_set),
                )?;
                core.run()?;

                // reverse callstack so root node is first
                let callstack: Vec<StackFrameInfo> = (&stack_frames)
                    .into_iter()
                    .rev()
                    .map(|frame| StackFrameInfo {
                        pc: frame
                            .pc
                            .try_into()
                            .expect("PC should not be larger than 64 bits"),
                    })
                    .collect();
                let sample = CallstackSample {
                    callstack,
                    time: std::time::Instant::now().duration_since(start),
                };

                samples.push(sample);

                if start.elapsed() > duration {
                    break;
                }

                // sleep a bit before next sample
                //TODO: make frequency configurable
                //TODO: subtract duration spent processing from sleep time
                std::thread::sleep(sampling_interval);
            }

            let profile = make_fx_profile(
                &vec![samples],
                &start_sys_time,
                &sampling_interval,
                executable_location,
            );

            let output_dir = std::env::current_dir()?;
            let profile_name = "probe-rs-profile";
            save_fx_profile(&profile, &output_dir, profile_name)?;

            Ok(())
        }
    }
}
