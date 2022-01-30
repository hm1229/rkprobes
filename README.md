# rkprobes
`rkprobes` helps you dynamically probe one or more functions and instructions in kernel



### APIs

```rust
// register a kprobe, need the address of the function or instruction, two handler functions and the type you want to probe
pub fn kprobe_register(addr: usize, handler: Arc<Mutex<dyn FnMut(&mut TrapFrame) + Send>>, post_handler: Option<Arc<Mutex<dyn FnMut(&mut TrapFrame) + Send>>>, probe_type: ProbeType) -> isize ;

//unregister address-related probe
pub fn kprobe_unregister(addr: usize) -> isize;

//trap handler for handler kprobes
pub fn kprobes_trap_handler(cx: &mut TrapFrame);
```



### Usage

- put `kprobes_trap_handler` in the trap_handler in your OS.

  ```rust
  pub fn trap_handler_no_frame(tf: &mut TrapFrame) {
      let scause = scause::read();
      match scause.cause() {
          Trap::Exception(E::Breakpoint) => rkprobes::kprobes_trap_handler(tf), //add here
      }
  }
  ```

- prepare `handler` and `post_handler`, `handler` is the function work before the probed function or instruction, `post_hanlder` is the function work after the probed function or instruction. `handler` is a must, while `post_handler` is a option, the parameter of these two handlers is a structure contains all the registers.

  ```rust
  pub fn example_pre_handler(cx: &mut TrapFrame){
      println!{"pre_handler: spec:{:#x}", cx.sepc};
  }
  
  pub fn example_post_handler(cx: &mut TrapFrame){
      println!{"post_handler: spec:{:#x}", cx.sepc};
  }
  ```

- to register a `kprobe` you need pass the address of the function or instruction ,the `handler` and `post_handler`(option) you prepared, the type of the probe way(function or instruction)

  ```rust
  pub enum ProbeType{
      Insn,
      Func,
  }
  
  rkprobes::kprobe_register(
      self.addr,
      alloc::sync::Arc::new(Mutex::new(move |cx: &mut TrapFrame| {
          example_pre_handler(cx);
      })),
      Some(alloc::sync::Arc::new(Mutex::new(move |cx: &mut TrapFrame| {
          example_post_handler(cx);
      }))),
      ProbeType::Insn,
  )
  ```
  
- to unregister a `kprobe` you just need to pass the address

  ```rust
  rkprobes::kprobe_unregister(self.addr)
  ```

  



### ToDo List

- [ ] divide `Func` type into `basic_func` and `async_fun`
- [ ] can get the parameters during parameter passing





author：hm

mentor：Xia Zhao, Yong Xiang

