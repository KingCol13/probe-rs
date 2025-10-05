use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use addr2line::Loader;
use anyhow::anyhow;
use debugid;
use fxprof_processed_profile as fxprofpp;
use itm::TracePacket;
use object;
use object::Object;
use object::ObjectSection;
use object::ObjectSegment;
use probe_rs::Session;
use probe_rs::config::Registry;
use probe_rs::{
    architecture::arm::{
        SwoConfig,
        component::{Dwt, TraceSink, enable_tracing, find_component},
        dp::DpAddress,
        memory::PeripheralType,
    },
    probe::list::Lister,
};
use probe_rs_debug::DebugInfo;
use probe_rs_debug::DebugRegisters;
use uuid::Uuid;

use crate::util::flash::{build_loader, run_flash_download};
use tracing::info;

#[derive(clap::Parser)]
pub struct ProfileCmd {
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
pub enum ProfileType {
    #[clap(name = "function")]
    #[clap(subcommand)]
    Function(FunctionProfileMethod),
    #[clap(name = "callstack")]
    #[clap(subcommand)]
    Callstack(CallstackProfileMethod),
}

#[derive(clap::Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FunctionProfileMethod {
    /// Naive, Halt -> Read PC -> Resume profiler
    #[clap(name = "naive")]
    Naive,
    /// Use the Itm port to profile the chip (ARM only)
    #[clap(name = "itm")]
    Itm {
        /// The speed of the clock feeding the TPIU/SWO module in Hz.
        clk: u32,
        /// The desired baud rate of the SWO output.
        baud: u32,
    },
    /// Use the DWT_PCSR to profile the chip (ARM only)
    #[clap(name = "pcsr")]
    Pcsr,
}

impl std::fmt::Display for FunctionProfileMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = format!("{self:?}");
        write!(f, "{}", s.to_lowercase())
    }
}

#[derive(clap::Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallstackProfileMethod {
    /// Naive frame pointer, halt -> walk callstack using fp -> resume
    NaiveFp,
    /// Naive dwarf debug, halt -> walk callstack using debug info -> resume
    NaiveDwarf,
}

impl std::fmt::Display for CallstackProfileMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = format!("{self:?}");
        write!(f, "{}", s.to_lowercase())
    }
}

fn function_profile(
    method: &FunctionProfileMethod,
    session: &mut Session,
    line_info: bool,
    duration: u64,
    core: usize,
    file_location: &Path,
    limit: usize,
) -> anyhow::Result<()> {
    // The error returned from try_from cannot be converted directly to anyhow::Error unfortunately,
    // due to a limitation in addr2line.
    let symbols = Symbols::try_from(file_location).map_err(|e| {
        anyhow!(
            "Failed to read symbol data from {}: {}",
            file_location.display(),
            e
        )
    })?;

    let start = Instant::now();
    let mut reads = 0;
    let mut samples: HashMap<u32, u64> = HashMap::with_capacity(256 * (duration as usize));
    let duration = Duration::from_secs(duration);

    match method {
        FunctionProfileMethod::Naive => {
            let mut core = session.core(core)?;
            core.reset()?;
            let pc_reg = core.program_counter();

            loop {
                core.halt(Duration::from_millis(10))?;
                let pc: u32 = core.read_core_reg(pc_reg)?;
                *samples.entry(pc).or_insert(1) += 1;
                reads += 1;
                core.run()?;
                if start.elapsed() > duration {
                    break;
                }
            }
        }
        FunctionProfileMethod::Pcsr => {
            enable_tracing(&mut session.core(core)?)?;

            let components = session.get_arm_components(DpAddress::Default)?;
            let component = find_component(&components, PeripheralType::Dwt)?;
            let interface = session.get_arm_interface()?;

            let mut dwt = Dwt::new(interface, component);
            dwt.enable()?;

            while start.elapsed() <= duration {
                let pc = dwt.read_pcsr()?;
                *samples.entry(pc).or_insert(1) += 1;
                reads += 1;
            }
        }
        FunctionProfileMethod::Itm { clk, baud } => {
            let sink = TraceSink::Swo(SwoConfig::new(*clk).set_baud(*baud));
            session.setup_tracing(core, sink)?;

            let components = session.get_arm_components(DpAddress::Default)?;
            let component = find_component(&components, PeripheralType::Dwt)?;
            let interface = session.get_arm_interface()?;
            let mut dwt = Dwt::new(interface, component);
            dwt.enable_pc_sampling()?;

            let decoder = itm::Decoder::new(
                session.swo_reader()?,
                itm::DecoderOptions { ignore_eof: true },
            );

            let iter = decoder.singles();

            for packet in iter {
                if let TracePacket::PCSample { pc: Some(pc) } = packet? {
                    *samples.entry(pc).or_insert(1) += 1;
                    reads += 1;
                }
                if start.elapsed() > duration {
                    break;
                }
            }
        }
    }

    let mut v = Vec::from_iter(samples);
    // sort by frequency
    v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));

    println!("Samples {reads}");

    for (address, count) in v.into_iter().take(limit) {
        let name = symbols
            .get_name(address as u64)
            .unwrap_or(format!("UNKNOWN - {address:08X}"));
        if line_info {
            let (file, num) = symbols
                .get_location(address as u64)
                .unwrap_or(("UNKNOWN", 0));
            println!("{file}:{num}");
        }
        println!(
            "{:>50} - {:.01}%",
            name,
            (count as f64 / reads as f64) * 100.0
        );
    }

    Ok(())
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

/// Algorithm from samply-symbols
fn debugid_from_identifier(identifier: &[u8], little_endian: bool) -> debugid::DebugId {
    // Truncate or zero-pad the indentifier to 16 bytes
    let mut d = [0u8; 16];
    let shared_len = identifier.len().min(d.len());
    d[0..shared_len].copy_from_slice(&identifier[0..shared_len]);

    // Pretend that the build ID was stored as a UUID with (u32, u16, u16) fields inside
    // the file. Parse those fields in the endianness of the file. Then use
    // Uuid::from_fields to serialize them as big endian.
    // For ELF build IDs this is a bit silly, because ELF build IDs aren't actually
    // field-based UUIDs, but this is what the tools in the breakpad and
    // sentry/symbolic universe do, so we do the same for compatibility with those
    // tools.
    let (d1, d2, d3) = if little_endian {
        (
            u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
            u16::from_le_bytes([d[4], d[5]]),
            u16::from_le_bytes([d[6], d[7]]),
        )
    } else {
        (
            u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
            u16::from_be_bytes([d[4], d[5]]),
            u16::from_be_bytes([d[6], d[7]]),
        )
    };
    let uuid = Uuid::from_fields(d1, d2, d3, d[8..16].try_into().unwrap());
    debugid::DebugId::from_uuid(uuid)
}

/// Algorithm from samply-symbols
fn debugid_from_text_first_page(text_first_page: &[u8], little_endian: bool) -> debugid::DebugId {
    const UUID_SIZE: usize = 16;
    const PAGE_SIZE: usize = 4096;
    let mut hash = [0; UUID_SIZE];
    for (i, byte) in text_first_page.iter().cloned().take(PAGE_SIZE).enumerate() {
        hash[i % UUID_SIZE] ^= byte;
    }
    debugid_from_identifier(&hash, little_endian)
}

fn get_elf_debugid(elf: &object::File) -> debugid::DebugId {
    if let Some(build_id) = elf.build_id().expect("Valid ELF file") {
        debugid_from_identifier(build_id, elf.is_little_endian())
    } else {
        // We were not able to locate a build ID, so fall back to creating a synthetic
        // identifier from a hash of the first page of the ".text" (program code) section.
        if let Some(section) = elf.section_by_name(".text") {
            let data_len = section.size().min(4096);
            if let Some(first_page_data) = section
                .data_range(section.address(), data_len)
                .expect("Valid ELF file")
            {
                debugid_from_text_first_page(first_page_data, elf.is_little_endian())
            } else {
                panic!(".text section too short")
            }
        } else {
            panic!("No .text section in ELF file")
        }
    }
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
    let debug_id = get_elf_debugid(&elf);

    let library_info = fxprofpp::LibraryInfo {
        name: binary_name.clone(),
        debug_name: binary_name.clone(),
        path: abs_binary_path.clone(),
        debug_path: abs_binary_path.clone(),
        debug_id,
        code_id: None,
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

fn callstack_profile(
    method: &CallstackProfileMethod,
    session: &mut Session,
    line_info: bool,
    duration: u64,
    core_idx: usize,
    file_location: &Path,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let start_sys_time = std::time::SystemTime::now();
    let mut samples: Vec<CallstackSample> = Vec::new();
    let duration = Duration::from_secs(duration);
    let debug_info = DebugInfo::from_file(file_location)?;

    let sampling_interval = Duration::from_millis(500);

    match method {
        CallstackProfileMethod::NaiveFp => todo!(),
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
                file_location,
            );

            let output_dir = std::env::current_dir()?;
            let profile_name = "probe-rs-profile";
            save_fx_profile(&profile, &output_dir, profile_name)?;

            Ok(())
        }
    }
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
            ProfileType::Function(method) => function_profile(
                &method,
                &mut session,
                self.line_info,
                self.duration,
                self.core,
                file_location,
                self.limit,
            ),
            ProfileType::Callstack(method) => callstack_profile(
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

// Wrapper around addr2line that allows to look up function names
pub(crate) struct Symbols {
    loader: Loader,
}

impl Symbols {
    pub fn try_from(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let loader = Loader::new(path)?;
        Ok(Self { loader })
    }

    /// Returns the name of the function at the given address, if one can be found.
    pub fn get_name(&self, addr: u64) -> Option<String> {
        // The basic steps here are:
        //   1. find which frame `addr` is in
        //   2. look up and demangle the function name
        //   3. if no function name is found, try to look it up in the object file
        //      directly
        //   4. return a demangled function name, if one was found
        let mut frames = self.loader.find_frames(addr).ok()?;

        frames
            .next()
            .ok()
            .flatten()
            .and_then(|frame| {
                frame
                    .function
                    .and_then(|name| name.demangle().map(|s| s.into_owned()).ok())
            })
            .or_else(|| self.loader.find_symbol(addr).map(|sym| sym.to_string()))
    }

    /// Returns the file name and line number of the function at the given address, if one can be.
    pub fn get_location(&self, addr: u64) -> Option<(&str, u32)> {
        // Find the location which `addr` is in. If we can determine a file name and
        // line number for this function we will return them both in a tuple.
        self.loader.find_location(addr).ok()?.and_then(|location| {
            let file = location.file?;
            let line = location.line?;

            Some((file, line))
        })
    }
}
