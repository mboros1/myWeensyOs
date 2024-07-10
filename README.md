CS 61 Problem Set 4
===================

**Fill out both this file and `AUTHORS.md` before submitting.** We grade
anonymously, so put all personally identifying information in `AUTHORS.md`.

Grading notes (if any)
----------------------



Extra credit attempted (if any)
-------------------------------
syscall_exit(pid), test in file p-kill.cc, run by pressing 't', same as p-forkexit but I call kill on a random pid rather then exit.
syscall_sleep(time), test in file p-sleep.cc, run by pressing 's', same as p-kill but sometimes sleeps a random thread.
    - visual is not too obvious because can't really tell if a thread is sleeping or just not running, but in the log the 
      amount of time slept is tracked, line starts with "Awaken", shows how many ticks the thread slept compared to how 
      long it actually slept
    - sometimes gets stuck in spinning forever if all the threads are sleeping or killed
