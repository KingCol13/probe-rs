use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use probe_rs::MemoryInterface;
use probe_rs_debug::DebugInfo;
use probe_rs_debug::DebugRegisters;

use fxprof_processed_profile as fxprofpp;
use probe_rs::Session;
use samply_object;

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
    /// Naively (halt -> walk -> resume) unwind callstack using dwarf debug information
    NaiveDwarf,
    /// Naively (halt -> walk -> resume) unwind callstack using frame pointers and frame record
    /// chain
    NaiveFramePointer,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    /// Firefox profiler output format that can be opened using:
    /// samply load probe-rs-profile.json.gz
    FirefoxProfiler,
}

impl std::fmt::Display for CallstackProfileMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = format!("{self:?}");
        write!(f, "{}", s.to_lowercase())
    }
}

#[derive(Clone, Copy, Debug)]
enum StackFrameInfo {
    ProgramCounter(u64),
    ReturnAddress(u64),
}

impl StackFrameInfo {
    fn to_fxprofpp_with_category(
        self: &StackFrameInfo,
        category: fxprofpp::CategoryHandle,
    ) -> fxprofpp::FrameInfo {
        let frame = match self {
            Self::ProgramCounter(addr) => fxprofpp::Frame::InstructionPointer(*addr),
            Self::ReturnAddress(addr) => fxprofpp::Frame::ReturnAddress(*addr),
        };

        fxprofpp::FrameInfo {
            frame: frame,
            category_pair: category.into(),
            flags: fxprofpp::FrameFlags::empty(),
        }
    }
}

/// A single sample containing a callstack and a time
#[derive(Clone, Debug)]
struct CallstackSample {
    // element 0 is root node
    // element 1 is first callee, etc
    callstack: Vec<StackFrameInfo>,
    // time since profiling started
    time: Duration,
}

/// All callstacks collected for a given core, for interfacing different sample collection methods
/// with different output formats
#[derive(Clone, Debug)]
struct CoreSamples {
    core: usize,
    callstacks: Vec<CallstackSample>,
}

impl CoreSamples {
    fn new(core: usize) -> Self {
        Self {
            core,
            callstacks: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MakeFxProfileError {
    #[error("Could not canonicalize ELF file path")]
    Canonicalize(#[source] std::io::Error),
    #[error("Invalid UTF-8 in ELF absolute file path")]
    InvalidUtf8,
    #[error("File name not found for ELF file")]
    NoFileStem,
    #[error("Could not parse ELF file")]
    ParseElf(#[source] object::Error),
    #[error("Could not generate debug ID for ELF")]
    DebugId,
}

fn make_fx_profile(
    core_callstacks: &[CoreSamples],
    start_time: &SystemTime,
    sampling_interval: &Duration,
    binary_path: &std::path::Path,
    elf_bytes: &[u8],
) -> Result<fxprofpp::Profile, MakeFxProfileError> {
    let start_timestamp = (*start_time).into();

    let abs_binary_path: String = binary_path
        .canonicalize()
        .map_err(|e| MakeFxProfileError::Canonicalize(e))?
        .to_str()
        .ok_or(MakeFxProfileError::InvalidUtf8)?
        .to_owned();

    let binary_name: String = binary_path
        .file_stem()
        .ok_or(MakeFxProfileError::NoFileStem)?
        .to_str()
        .expect("Abs path converted to UTF-8 so file stem should too")
        .to_owned();

    let mut profile = fxprofpp::Profile::new(
        // TODO: give this a better name
        &binary_name,
        start_timestamp,
        (*sampling_interval).into(),
    );

    let category = profile.add_category("raw", fxprofpp::CategoryColor::Yellow);

    let process = profile.add_process(
        "process",
        0,
        fxprofpp::Timestamp::from_nanos_since_reference(0),
    );

    let elf = object::File::parse(&*elf_bytes).map_err(|e| MakeFxProfileError::ParseElf(e))?;
    let debug_id = samply_object::debug_id_for_object(&elf).ok_or(MakeFxProfileError::DebugId)?;
    let code_id = samply_object::code_id_for_object(&elf);

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

    let start_avma = samply_object::relative_address_base(&elf);
    profile.add_lib_mapping(process, library, start_avma, u64::MAX, 0);

    for CoreSamples { core, callstacks } in core_callstacks.iter() {
        //TODO: check whether is_main should be set or not
        let thread = profile.add_thread(
            process,
            *core as u32,
            fxprofpp::Timestamp::from_nanos_since_reference(0),
            false,
        );
        for sample in callstacks {
            let stack_frames = sample
                .callstack
                .iter()
                .map(|frame| frame.to_fxprofpp_with_category(category));
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

    Ok(profile)
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
    let duration = Duration::from_secs(duration);
    let sampling_interval = Duration::from_nanos(interval_ns);

    let elf_bytes = std::fs::read(executable_location)?;
    let debug_info = DebugInfo::from_raw(&elf_bytes)?;

    let available_cores: Vec<_> = session.list_cores().iter().map(|c| c.0).collect();

    let cores = if cores.is_empty() {
        &available_cores
    } else {
        cores
    };

    let mut samples: Vec<CoreSamples> = cores
        .iter()
        .map(|core_idx| CoreSamples::new(*core_idx))
        .collect();

    let start = Instant::now();
    let start_sys_time = std::time::SystemTime::now();

    loop {
        // TODO: all cores should be stopped simultaneously before samples are collected for more
        // accurate results
        for core_sample in samples.iter_mut() {
            let mut core = session.core(core_sample.core)?;

            // collect sample
            core.halt(Duration::from_millis(10))?;
            let callstack = match method {
                CallstackProfileMethod::NaiveDwarf => dwarf_unwind(&mut core, &debug_info),
                CallstackProfileMethod::NaiveFramePointer => frame_pointer_stack_walk(&mut core),
            };
            core.run()?;

            let sample = CallstackSample {
                callstack,
                time: std::time::Instant::now().duration_since(start),
            };

            core_sample.callstacks.push(sample);
        }

        if start.elapsed() > duration {
            break;
        }

        // sleep a bit before next sample
        std::thread::sleep(sampling_interval);
    }

    let profile = make_fx_profile(
        &samples,
        &start_sys_time,
        &sampling_interval,
        executable_location,
        &elf_bytes,
    )?;

    let output_dir = std::env::current_dir()?;
    let profile_name = "probe-rs-profile";
    save_fx_profile(&profile, &output_dir, profile_name)?;

    Ok(())
}

fn dwarf_unwind<'a>(
    core: &mut probe_rs::Core<'a>,
    debug_info: &probe_rs_debug::DebugInfo,
) -> Vec<StackFrameInfo> {
    let debug_registers = DebugRegisters::from_core(core);
    let exception_handler = probe_rs_debug::exception_handler_for_core(core.core_type());
    let instruction_set = core.instruction_set().unwrap();
    let stack_frames = debug_info
        .unwind(
            core,
            debug_registers,
            exception_handler.as_ref(),
            Some(instruction_set),
            usize::MAX,
        )
        .unwrap_or_else(|_| {
            // empty sample if unwind fails
            tracing::debug!("Unable to unwind, discarding callstack");
            Vec::new()
        });

    // filter out inlined functions since they do not need to be recorded (they can be added at
    // symbolication time)
    // reverse callstack so root node is first
    let stack_frames: Vec<StackFrameInfo> = (&stack_frames)
        .into_iter()
        .enumerate()
        .filter(|(idx, frame)| *idx == 0 || !frame.is_inlined)
        .map(|(idx, frame)| {
            let addr: u64 = frame
                .pc
                .try_into()
                .expect("PC should not be larger than 64 bits");

            match idx {
                0 => StackFrameInfo::ProgramCounter(addr),
                _ => StackFrameInfo::ReturnAddress(addr),
            }
        })
        .rev()
        .collect();

    stack_frames
}

fn read_mem<'a>(core: &mut probe_rs::Core<'a>, addr: u64) -> u64 {
    if core.is_64_bit() {
        core.read_word_64(addr).unwrap()
    } else {
        core.read_word_32(addr).unwrap() as u64
    }
}

// TODO: make this work outside of arm-32bit
// RISC-V needs different handling - fp and ra swapped
fn frame_pointer_stack_walk<'a>(core: &mut probe_rs::Core<'a>) -> Vec<StackFrameInfo> {
    let mut stack_frames = Vec::new();

    let mut frame_pointer: u64 = core.read_core_reg(core.frame_pointer()).unwrap();
    let program_counter: u64 = core.read_core_reg(core.program_counter()).unwrap();

    stack_frames.push(StackFrameInfo::ProgramCounter(program_counter));

    while frame_pointer != 0 {
        let return_addr = read_mem(core, frame_pointer + 4);
        stack_frames.push(StackFrameInfo::ReturnAddress(return_addr));
        frame_pointer = read_mem(core, frame_pointer);
    }

    stack_frames.into_iter().rev().collect()
}
