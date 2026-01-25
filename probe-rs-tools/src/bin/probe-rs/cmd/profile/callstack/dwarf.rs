use probe_rs_debug::DebugRegisters;

use super::StackFrameInfo;

pub fn dwarf_unwind<'a>(
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
    let stack_frames: Vec<StackFrameInfo> = stack_frames
        .iter()
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
