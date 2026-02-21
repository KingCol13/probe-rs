// This code is adapted from code in `framehop`
use gimli::{CieOrFde, Reader, UnwindOffset, UnwindSection};

use gimli::BaseAddresses;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfCfiIndexError {
    Gimli(gimli::Error),
    FdeOffsetTooBig,
}

impl core::fmt::Display for DwarfCfiIndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gimli(e) => write!(f, "EhFrame processing failed: {e}"),
            Self::FdeOffsetTooBig => write!(f, "FDE offset did not fit into u32"),
        }
    }
}

impl From<gimli::Error> for DwarfCfiIndexError {
    fn from(e: gimli::Error) -> Self {
        Self::Gimli(e)
    }
}

impl std::error::Error for DwarfCfiIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gimli(e) => Some(e),
            _ => None,
        }
    }
}

/// A binary search table for eh_frame FDEs. We generate this whenever a module
/// without eh_frame_hdr is added.
pub struct DwarfCfiIndex {
    /// Contains the initial address for every FDE.
    /// This vector is sorted so that it can be used for binary search.
    /// It has the same length as `fde_offsets`.
    sorted_fde_pc_starts: Vec<u64>,
    /// Contains the FDE offset for every FDE. The FDE at offset `fde_offsets[i]`
    /// has a PC range which starts at `sorted_fde_pc_starts[i]`.
    fde_offsets: Vec<u32>,
}

impl DwarfCfiIndex {
    pub fn try_new<R, US>(unwind_section: &US) -> Result<Self, DwarfCfiIndexError>
    where
        R: Reader,
        R::Offset: TryInto<u32>,
        US: UnwindSection<R>,
    {
        let bases = BaseAddresses::default();
        let mut fde_pc_and_offset = Vec::new();

        let mut cur_cie = None;
        let mut entries_iter = unwind_section.entries(&bases);
        while let Some(entry) = entries_iter.next()? {
            let fde = match entry {
                CieOrFde::Cie(cie) => {
                    cur_cie = Some(cie);
                    continue;
                }
                CieOrFde::Fde(partial_fde) => {
                    partial_fde.parse(|unwind_section, bases, cie_offset| {
                        if let Some(cie) = &cur_cie
                            && cie.offset()
                                == <US::Offset as UnwindOffset<R::Offset>>::into(cie_offset)
                        {
                            return Ok(cie.clone());
                        }
                        let cie = unwind_section.cie_from_offset(bases, cie_offset);
                        if let Ok(cie) = &cie {
                            cur_cie = Some(cie.clone());
                        }
                        cie
                    })?
                }
            };
            let pc = fde.initial_address();
            let fde_offset = <R::Offset as TryInto<u32>>::try_into(fde.offset())
                .map_err(|_| DwarfCfiIndexError::FdeOffsetTooBig)?;
            fde_pc_and_offset.push((pc, fde_offset));
        }
        fde_pc_and_offset.sort_by_key(|(pc, _)| *pc);
        let sorted_fde_pc_starts = fde_pc_and_offset.iter().map(|(pc, _)| *pc).collect();
        let fde_offsets = fde_pc_and_offset.into_iter().map(|(_, fde)| fde).collect();
        Ok(Self {
            sorted_fde_pc_starts,
            fde_offsets,
        })
    }

    pub(crate) fn fde_offset_for_relative_address(&self, lookup_address: u64) -> Option<u32> {
        let i = match self.sorted_fde_pc_starts.binary_search(&lookup_address) {
            Err(0) => return None,
            Ok(i) => i,
            Err(i) => i - 1,
        };
        Some(self.fde_offsets[i])
    }
}
