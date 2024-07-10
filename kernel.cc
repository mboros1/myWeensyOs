#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // (re-)initialize kernel page table
    for (vmiter it(kernel_pagetable);
         it.va() < MEMSIZE_VIRTUAL;
         it += PAGESIZE) {
        if (it.va() >= PROC_START_ADDR || it.va() == CONSOLE_ADDR){
            it.map(it.va(), PTE_P | PTE_W | PTE_U);
        }
        else if (it.va() != 0) {
            it.map(it.va(), PTE_P | PTE_W);
        } else {
            // nullptr is inaccessible even to the kernel
            it.map(it.va(), 0);
        }
    }

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to the first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory, or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You'll
//    probably want to reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The handout code returns the next allocatable free page it can find.
//    It never reuses pages or supports freeing memory (you'll change that).

static uintptr_t next_alloc_pa;

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    uintptr_t counter = 0;
    while (next_alloc_pa < MEMSIZE_PHYSICAL) {
        uintptr_t pa = next_alloc_pa;
        next_alloc_pa += PAGESIZE;
        counter += PAGESIZE;

        if (allocatable_physical_address(pa)
            && !pages[pa / PAGESIZE].used()) {
            pages[pa / PAGESIZE].refcount++;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }

        if (next_alloc_pa == MEMSIZE_PHYSICAL){
            next_alloc_pa = PAGESIZE;
        }
        if (counter > MEMSIZE_PHYSICAL + PAGESIZE) return nullptr;
    }
    return nullptr;
}


// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    assert((uintptr_t)kptr % PAGESIZE == 0);
    assert((uintptr_t)kptr < MEMSIZE_VIRTUAL);
    assert((uintptr_t)kptr != 0);
    assert(pages[(size_t)kptr / PAGESIZE].refcount > 0);

    if (pages[(size_t)kptr / PAGESIZE].refcount != 1 &&
      (uintptr_t)kptr != 0x5000 && (uintptr_t)kptr != 0x6000)
      log_printf("free addr: %p refcount: %d\n", kptr, pages[(size_t)kptr / PAGESIZE].refcount);
    pages[(size_t)kptr / PAGESIZE].refcount--;
    next_alloc_pa = 0;
}


// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);
    // - 4-level skeleton
    x86_64_pagetable* pt = (x86_64_pagetable*)kalloc(PAGESIZE);
    if (!pt) return;
    memset(pt, 0, PAGESIZE);
    ptable[pid].pagetable = pt;

    // - actual entries
    for (uintptr_t a = 0; a != PROC_START_ADDR; a += PAGESIZE) {
        vmiter(pt, a).map(a, a ? PTE_P | PTE_W : 0);
    }
    vmiter(pt, CONSOLE_ADDR).map(CONSOLE_ADDR, PTE_P | PTE_W | PTE_U);

    // load the program
    program_loader loader(program_name);

    // allocate, map all memory, copy instructions and data into place
    for (loader.reset(); loader.present(); ++loader) {
        for (uintptr_t a = round_down(loader.va(), PAGESIZE), i = 0;
             a < loader.va() + loader.size();
             a += PAGESIZE, ++i) {
            uintptr_t pa = (uintptr_t)kalloc(PAGESIZE);
            if (!pa) return;
            memcpy((void*)pa, loader.data() + i*PAGESIZE, PAGESIZE);
            if (loader.writable()){
              vmiter(pt, a).map(pa, PTE_P | PTE_W | PTE_U);
            } else {
              vmiter(pt, a).map(pa, PTE_P | PTE_U);
            }
        }
    }
    
    // mark entry point
    ptable[pid].regs.reg_rip = loader.entry();

    // allocate stack
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;
    
    uintptr_t addr = (uintptr_t)kalloc(PAGESIZE);
    if (!addr) return;
    memset((void*) addr, 0, PAGESIZE);
    vmiter(pt, stack_addr).map(addr, PTE_P | PTE_W | PTE_U);

    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }


    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

int syscall_page_alloc(uintptr_t addr);
int syscall_fork();
int syscall_exit(pid_t pid);
int syscall_kill(pid_t pid);
int syscall_sleep(size_t time);

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
     log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip);

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        panic(nullptr);         // does not return

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();
    case SYSCALL_EXIT:
        return syscall_exit(current->pid);
    case SYSCALL_KILL:
        return syscall_kill(current->regs.reg_rdi);
    case SYSCALL_SLEEP:
        return syscall_sleep(current->regs.reg_rdi);
    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Handles the SYSCALL_PAGE_ALLOC system call. This function
//    should implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the handout code, it does not).

int syscall_page_alloc(uintptr_t addr) {
    if (addr > MEMSIZE_VIRTUAL) return -1;
    if (addr % 4096 != 0) return -1;
    
    x86_64_pagetable* pt = current->pagetable;
    uintptr_t a = (uintptr_t)kalloc(PAGESIZE);
    if (!a) {
      log_printf("ERROR:sys_page_alloc failed kalloc; proc: %d addr: %p\n", current->pid, addr);
      return - 1;
    }
    memset((void*)a, 0, PAGESIZE);
    vmiter it(pt, addr);
    if (it.present()){
      kfree((void*)it.pa());
    }
    int tm = it.try_map(a, PTE_P | PTE_W | PTE_U);
    if (tm == -1) {
      log_printf("ERROR:sys_page_alloc failed map; proc: %d addr: %p\n", current->pid, addr);
      kfree(pt);
      return -1;
    }
    return 0;
}

// clean_up_memory(pt)
//    Frees all memory connected to this page table,
//    used in sys_exit and to clean up failed forks
int clean_up_memory(x86_64_pagetable* pt);


// syscall_fork()
//    Handles the SYSCALL_FORK system call.

int syscall_fork() {
    pid_t pid = 0;
    for(int i=1; i < NPROC; ++i){
        if (ptable[i].state == P_FREE) {
          pid = i;
          break;
        }
    }
    if (!pid) return -1;
    
    ptable[pid].state = P_BLOCKED;
    x86_64_pagetable* pt = (x86_64_pagetable*)kalloc(PAGESIZE);
    if (!pt) {
        log_printf("ERROR:fork failed initial kalloc: exiting: fork: %d pid: %d\n", current->pid, pid);
        ptable[pid].state = P_FREE;
        return -1;
    }
    memset((void*)pt,0,PAGESIZE);
    ptable[pid].pagetable = pt;
    
    vmiter src(current->pagetable);
    vmiter dest(pt);
    while (src.va() < MEMSIZE_VIRTUAL){
      if (src.user() && src.writable()){
        if (src.va() == CONSOLE_ADDR){
          int tm = dest.try_map(CONSOLE_ADDR, src.perm());
          if (tm == -1){
            int clean = clean_up_memory(pt);
            assert(clean == 0);
            log_printf("ERROR:map failed in fork copying src to dest: current: %d pid: %d addr %p\n", current->pid, pid, src.perm());
            ptable[pid].state = P_FREE;
            return -1;
          };
        } else {
          void* dest_data = kalloc(PAGESIZE);
          if (!dest_data) {
            int clean = clean_up_memory(pt);
            assert(clean == 0);
            log_printf("ERROR:map failed in fork copying src to dest: current: %d pid: %d addr %p\n", current->pid, pid, src.perm());
            ptable[pid].state = P_FREE;
            return -1;
          }
          memset(dest_data, 0, PAGESIZE);
          memcpy(dest_data, (void*)src.pa(), PAGESIZE);
          int tm = dest.try_map((uintptr_t)dest_data, src.perm());
          if (tm == -1){
            int clean = clean_up_memory(pt);
            assert(clean == 0);
            log_printf("ERROR:map failed in fork copying src to dest: current: %d pid: %d addr %p\n", current->pid, pid, src.perm());
            ptable[pid].state = P_FREE;
            kfree(dest_data);
            return -1;
          }
        }
      } else {
        int tm = dest.try_map(src.pa(), src.perm());
        if (tm == -1){
          int clean = clean_up_memory(pt);
          assert(clean == 0);
          log_printf("ERROR:map failed in fork copying src to dest: current: %d pid: %d addr %p\n", current->pid, pid, src.perm());
          ptable[pid].state = P_FREE;
          return -1;
        }

        if (src.user() && !src.writable()){
          pages[src.pa() / PAGESIZE].refcount++;
        }
      }
      src+=PAGESIZE;
      dest+=PAGESIZE;
    }

    // copying all registers except rax
    ptable[pid].regs = current->regs;
    ptable[pid].regs.reg_rax = 0;

    ptable[pid].state = P_RUNNABLE;
    ptable[pid].pid = pid;

    log_printf("forked: %d new: %d pt: %p \n", current->pid, pid, pt);
    return pid;
}

// syscall_exit(pid)
//    Handles the SYSCALL_EXIT system call.
int syscall_exit(pid_t pid){
    ptable[pid].state = P_BLOCKED;
    int clean = clean_up_memory(ptable[pid].pagetable);
    assert(clean == 0);
    ptable[pid].state = P_FREE;
    if (pid == current->pid)
      schedule();
    return 0;
}

// syscall_kill(pid)
//    Handles the SYSCALL_KILL system call.
//    Checks if pid belongs to a valid process,
//    then kills it with syscall_exit.
int syscall_kill(pid_t pid){
    if (ptable[pid].state == P_BLOCKED || ptable[pid].state == P_RUNNABLE ||
        ptable[pid].state == P_SLEPT){
      int ret = syscall_exit(pid);
      if (ret == 0){
        log_printf("killed process: pid: %d state: %d current: %d state: %d\n", 
            pid, ptable[pid].state, current->pid, current->state);
      }
      return ret;
    } else {
      log_printf("ERROR:failed to kill process: pid: %d state: %d current: %d state: %d\n", 
          pid, ptable[pid].state, current->pid, current->state);
      return -1;
    }
}

// syscall_sleep(time)
//    makes a thread sleep for 'time' ticks
int syscall_sleep(size_t time){
  log_printf("sleeping %ld\n", time);
  current->sleep_ts = ticks.load();
  current->sleep_time = time;
  current->state = P_SLEPT;
  schedule();
  return 0;
}

// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_SLEPT) {
           size_t time_slept = ticks.load() - ptable[pid].sleep_ts;
           if (time_slept >= ptable[pid].sleep_time){
             log_printf("Awaken sleeping thread; pid:%d time slept:%ld expected sleep time:%ld\n", pid, time_slept, ptable[pid].sleep_time);
             ptable[pid].state = P_RUNNABLE;
           }
        }
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("Spinning forever... %u\n", spins);
        }
    }
}


// run(p)
//    Run process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    //log_printf("proc: %d, pt: %p\n", current->pid, current->pagetable);
    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// definition in `k-memviewer.cc`
void console_memviewer(proc* vmp);

// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    console_memviewer(p);
}


int clean_up_memory(x86_64_pagetable* pt){
    for(vmiter it(pt); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE){
      if (it.pa() == CONSOLE_ADDR) continue;
      else if (it.user())  {
        kfree((void*)it.pa());
      }
    }
    for(ptiter it(pt); it.active(); it.next()){
        kfree((void*)it.pa());
    }
    kfree((void*)pt);
    return 0;
}
