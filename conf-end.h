/*
 * End of configuration stuff for PD ksh.
 *
 * RCSid: $Id$
 */

#if defined(EMACS) || defined(VI)
# define	EDIT
#else
# undef		EDIT
#endif

/* Editing implies history */
#if defined(EDIT) && !defined(HISTORY)
# define HISTORY
#endif /* EDIT */

/*
 * if you don't have mmap() you can't use Peter Collinson's history
 * mechanism.  If that is the case, then define EASY_HISTORY
 */
#if defined(HISTORY) && (!defined(COMPLEX_HISTORY) || !defined(HAVE_MMAP) || !defined(HAVE_FLOCK))
# undef COMPLEX_HISTORY
# define EASY_HISTORY			/* sjg's trivial history file */
#endif

/* Can we safely catch sigchld and wait for processes? */
#if (defined(HAVE_WAITPID) || defined(HAVE_WAIT3)) \
    && (defined(POSIX_SIGNALS) || defined(BSD42_SIGNALS))
# define JOB_SIGS
#endif

#if !defined(JOB_SIGS) || !(defined(POSIX_PGRP) || defined(BSD_PGRP))
# undef JOBS /* if no JOB_SIGS, no job control support */
#endif

/* pdksh assumes system calls return EINTR if a signal happened (this so
 * the signal handler doesn't have to longjmp()).  I don't know if this
 * happens (or can be made to happen) with sigset() et. al. (the bsd41 signal
 * routines), so, the autoconf stuff checks what they do and defines
 * SIGNALS_DONT_INTERRUPT if signals don't interrupt read().
 * If SIGNALS_DONT_INTERRUPT isn't defined and your compiler chokes on this,
 * delete the hash in front of the error (and file a bug report).
 */
#ifdef SIGNALS_DONT_INTERRUPT
  # error pdksh needs interruptable system calls.
#endif /* SIGNALS_DONT_INTERRUPT */

#ifdef HAVE_GCC_FUNC_ATTR
# define GCC_FUNC_ATTR(x)	__attribute__((x))
# define GCC_FUNC_ATTR2(x,y)	__attribute__((x,y))
#else
# define GCC_FUNC_ATTR(x)
# define GCC_FUNC_ATTR2(x,y)
#endif /* HAVE_GCC_FUNC_ATTR */

#ifdef OS2
/* Due to a combination of two features, we might steal keys from the kid:
   a) TERMIOS interface is implemented via a thread which constantly
      reads-ahead from the keyboard.  The thread is auto-switched off for
      syncroneously executed kids, but not for asyncroneous ones.  This
      thread is *not* switched off after it starts.  TERMIO interface
      grants a flag in c_lflags which switches this thread off when
      restoring the state.

   b) we execute kids asyncroneously.  Otherwise the following may happen:
      the kid could forget to register itself as a target for Control-Break
      (e.g., ping).  Then it is we who gets Control-Break and dies.  By
      the semantic of OS/2 program exit, this leaves ourselves as zombies until
      the kid terminates (and the kid unkillable).
      Running kids asyncroneously allows up to we catch signals during the
      kid execution, and pass them to the kid by force in the case it is
      us who received the signal.
 */
# undef HAVE_TERMIOS_H
# ifndef HAVE_TERMIO_H
#  define HAVE_TERMIO_H
# endif
#endif
