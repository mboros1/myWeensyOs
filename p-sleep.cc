#include "u-lib.hh"
#ifndef ALLOC_SLOWDOWN
#define ALLOC_SLOWDOWN 18
#endif

extern uint8_t end[];

// These global variables go on the data page.
uint8_t* heap_top;
uint8_t* stack_bottom;

/* Test for syscall_kill(pid), basically the same as fork_exit
 * but will call kill on a random pid until it finds an active one
 * rather then calling exit
 */
void process_main() {
    while (true) {
        int x = rand(0, ALLOC_SLOWDOWN);
        if (x == 0) {
            // fork, then either kill or start allocating
            pid_t p = sys_fork();
            int choice = rand(0, 2);
            if (choice == 0 && p > 0) {
                int status = -1;
                do {
                int pid = rand(1,16);
                status = sys_kill(pid);
                } while(status == -1);
            } else if (choice != 2 ? p > 0 : p == 0) {
                size_t time = (size_t)rand(0,100);
                sys_sleep(time);
                break;
            }
        } else {
            sys_yield();
        }
    }

    int speed = rand(1, 16);

    uint8_t* data_top = (uint8_t*) round_up((uintptr_t) end, PAGESIZE);
    heap_top = data_top;
    stack_bottom = (uint8_t*) round_down((uintptr_t) rdrsp() - 1, PAGESIZE);
    unsigned nalloc = 0;

    // Allocate heap pages until out of address space,
    // forking along the way.
    while (heap_top != stack_bottom) {
        if (rand(0, 6 * ALLOC_SLOWDOWN) >= 8 * speed) {
            size_t time = (size_t)rand(0,100);
            sys_sleep(time);
            sys_yield();
            continue;
        }

        int x = rand(0, 7 + min(nalloc / 4, 10U));
        if (x < 2) {
            if (sys_fork() == 0) {
                size_t time = (size_t)rand(0,100);
                sys_sleep(time);
                speed = rand(1, 16);
            }
        } else if (x < 3) {
            int status = -1;
            do {
            int pid = rand(1,16);
            status = sys_kill(pid);
            } while(status == -1);
        } else if (sys_page_alloc(heap_top) >= 0) {
            *heap_top = speed;
            console[CPOS(24, 79)] = speed;
            heap_top += PAGESIZE;
            if (console[CPOS(24, 0)]) {
                // clear "Out of physical memory" msg
                console_printf(CPOS(24, 0), 0, "\n");
            }
            nalloc = (heap_top - data_top) / PAGESIZE;
        } else if (nalloc < 4) {
            int status = -1;
            do {
              int pid = rand(1,16);
              status = sys_kill(pid);
            } while(status == -1);
        } else {
            nalloc -= 4;
        }
    }

    // After running out of memory
    while (true) {
        if (rand(0, 2 * ALLOC_SLOWDOWN - 1) == 0) {
            int status = -1;
            do {
              int pid = rand(1,16);
              status = sys_kill(pid);
            } while(status == -1);
        } else {
            sys_yield();
        }
    }
}
