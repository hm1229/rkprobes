use riscv_decode::{decode, Instruction, instruction_length};

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    // "C" (Compressed) extension
    CADDI4SPN,
    CADDI,
    CNOP,
    CFLD,
    CLW,
    CLD,
    CSW,
    CSD,
    CADDIW,
    CLI,
    CADDI16SP,
    CLUI,
    CSRLI,
    CSRAI,
    CANDI,
    CSUB,
    CXOR,
    COR,
    CAND,
    CSUBW,
    CADDW,
    CJ,
    CBEQZ,
    CBNEZ,
    CSLLI,
    CLWSP,
    CLDSP,
    CJR,
    CMV,
    CBREAK,
    CJALR,
    CADD,
    CSWSP,
    CSDSP,
    CEBREAK,
    NOTFOUND,
}

pub enum InsnStatus {
    Illegal,
    Legal,
}

pub fn insn_decode(addr: usize) -> InsnStatus{
    let addr_32 = unsafe{core::slice::from_raw_parts(addr as *const u32, 1)};
    if addr_32[0] & 0b11 != 0b11{
        let addr_16 = unsafe{core::slice::from_raw_parts(addr as *const u16, 1)};
        match c_decode(addr_16[0]){
            Opcode::CJ => return InsnStatus::Illegal,
            Opcode::CJR => return InsnStatus::Illegal,
            Opcode::CJALR => return InsnStatus::Illegal,
            Opcode::CBEQZ => return InsnStatus::Illegal,
            Opcode::CBNEZ => return InsnStatus::Illegal,
            Opcode::CEBREAK => return InsnStatus::Illegal,
            Opcode::NOTFOUND => {},
            _ => return InsnStatus::Legal,
        }
    }
    match decode(addr_32[0]){
        Ok(Instruction::Ecall) => InsnStatus::Illegal,
        Ok(Instruction::Ebreak) => InsnStatus::Illegal,
        Ok(Instruction::Uret) => InsnStatus::Illegal,
        Ok(Instruction::Sret) => InsnStatus::Illegal,
        Ok(Instruction::Mret) => InsnStatus::Illegal,
        Ok(Instruction::Wfi) => InsnStatus::Illegal,
        Ok(Instruction::SfenceVma(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrc(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrw(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrs(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrsi(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrwi(_)) => InsnStatus::Illegal,
        Ok(Instruction::Csrrci(_)) => InsnStatus::Illegal,
        Ok(Instruction::Fence(_)) => InsnStatus::Illegal,
        Ok(Instruction::FenceI) => InsnStatus::Illegal,
        Ok(Instruction::Auipc(_)) => InsnStatus::Illegal,
        Ok(Instruction::Beq(_)) => InsnStatus::Illegal,
        Ok(Instruction::Bne(_)) => InsnStatus::Illegal,
        Ok(Instruction::Bltu(_)) => InsnStatus::Illegal,
        Ok(Instruction::Bge(_)) => InsnStatus::Illegal,
        Ok(Instruction::Bltu(_)) => InsnStatus::Illegal,
        Ok(Instruction::Bgeu(_)) => InsnStatus::Illegal,
        Err(_) => InsnStatus::Illegal,
        _ => InsnStatus::Legal,
    }
}

pub fn c_decode(base: u16) -> Opcode {
    let op_low = base & 0b11;
    let op_high = (base >> 13) & 0b111;

    match (op_high, op_low) {
        (0b000, 0b00) => Opcode::CADDI4SPN,
        (0b000, 0b01) => {
            if (base >> 7) & 0b11111 == 0 {
                Opcode::CNOP
            } else {
                Opcode::CADDI
            }
        }
        (0b001, 0b00) => Opcode::CFLD, // or is it C.LQ?
        (0b010, 0b00) => Opcode::CLW,
        (0b011, 0b00) => Opcode::CLD,
        (0b110, 0b00) => Opcode::CSW,
        (0b111, 0b00) => Opcode::CSD,
        (0b001, 0b01) => Opcode::CADDIW,
        (0b010, 0b01) => Opcode::CLI,
        (0b011, 0b01) => {
            if (base >> 7) & 0b11111 == 2 {
                Opcode::CADDI16SP
            } else {
                Opcode::CLUI
            }
        }
        (0b100, 0b01) => {
            let func3 = (base >> 10) & 0b111;
            let func2 = (base >> 5) & 0b11;
            match (func3, func2) {
                (0b000, _) | (0b100, _) => Opcode::CSRLI,
                (0b001, _) | (0b101, _) => Opcode::CSRAI,
                (0b010, _) | (0b110, _) => Opcode::CANDI,
                (0b011, 0b00) => Opcode::CSUB,
                (0b011, 0b01) => Opcode::CXOR,
                (0b011, 0b10) => Opcode::COR,
                (0b011, 0b11) => Opcode::CAND,
                (0b111, 0b00) => Opcode::CSUBW,
                (0b111, 0b01) => Opcode::CADDW,
                _ => Opcode::NOTFOUND,
            }
        }
        (0b101, 0b01) => Opcode::CJ,
        (0b110, 0b01) => Opcode::CBEQZ,
        (0b111, 0b01) => Opcode::CBNEZ,
        (0b000, 0b10) => Opcode::CSLLI,
        (0b010, 0b10) => Opcode::CLWSP,
        (0b011, 0b10) => Opcode::CLDSP,
        (0b100, 0b10) => {
            let func12 = (base >> 12) & 0b1;
            let func11_7 = (base >> 7) & 0b11111;
            let func6_2 = (base >> 2) & 0b11111;

            match (func12, func11_7, func6_2) {
                (0b0, _, 0b00000) => Opcode::CJR,
                (0b0, _, _) => Opcode::CMV,
                (0b1, 0b0, 0b00000) => Opcode::CEBREAK,
                (0b1, _, 0b00000) => Opcode::CJALR,
                (0b1, _, _) => Opcode::CADD,
                spec => Opcode::NOTFOUND,
            }
        }
        (0b110, 0b10) => Opcode::CSWSP,
        (0b111, 0b10) => Opcode::CSDSP,

        _ => Opcode::NOTFOUND,
    }
}

pub fn get_insn_length(addr: usize) -> usize{
    let addr = unsafe{core::slice::from_raw_parts(addr as *const u16, 1)};
    instruction_length(addr[0])
}