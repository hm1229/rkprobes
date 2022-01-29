#![no_std]
#![feature(naked_functions)]
#![feature(asm)]

#[macro_use]
extern crate log;
extern crate alloc;

mod kprobes;
mod riscv_insn_decode;

use alloc::sync::Arc;
pub use kprobes::kprobes_trap_handler;
use spin::Mutex;
use trapframe::TrapFrame;
pub use kprobes::ProbeType;

pub fn kprobe_register(addr: usize, handler: Arc<Mutex<dyn FnMut(&mut TrapFrame) + Send>>, post_handler: Option<Arc<Mutex<dyn FnMut(&mut TrapFrame) + Send>>>, probe_type: ProbeType) -> isize {
    kprobes::KPROBES.register_kprobe(addr, handler, post_handler, probe_type)
}

pub fn kprobe_unregister(addr: usize) -> isize {
    kprobes::KPROBES.unregister_kprobe(addr)
}