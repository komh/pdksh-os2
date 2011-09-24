#define INCL_DOS
#define INCL_DOSERRORS
#define INCL_DOSSESMGR
#define INCL_WINPROGRAMLIST
#define INCL_WINFRAMEMGR
#include <os2.h>
#include "config.h"
#include "sh.h"				/* To get inDOS(). */
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>

static int isfullscreen(void)
{
  PTIB ptib;
  PPIB ppib;

  DosGetInfoBlocks(&ptib, &ppib);
  return (ppib -> pib_ultype != SSF_TYPE_WINDOWABLEVIO);
}

static int
quoted_strlen(char *s)
{
    int ret = 0;
    int seen_space = 0;
    while (*s) {
	if (seen_space == 0 && *s == ' ') {
	    ret += 2;
	    seen_space = 1;
	} else if (*s == '\"') {
	    if (seen_space == 0) {
		seen_space = 1;
		ret += 4;
	    } else ret += 2;
	} else ret++;
	s++;
    }
    return ret;
}

static char *
quoted_strcpy(char *targ, char* src)
{
    int seen_space = 0;
    char *s = src, *t = targ;
    
    while (*s) {
	if ((*s == ' ') || (*s == '\"')) {
	    seen_space = 1;
	    break;
	}
	s++;
    }
    if (seen_space) {
	*targ++ = '\"';
    }
    while (*src) {
	if (*src == '\"') {
	    *targ++ = '\\';
	} 
	*targ++ = *src++;
    }
    if (seen_space) {
	*targ++ = '\"';
    }
    *targ = '\0';
    return t;
}

static int 
newsession(int type, int mode, char *cmd, char **args, char **env)
{
  STARTDATA sd;
  REQUESTDATA qr;
  ULONG sid, pid, len, cnt, rc;
  PVOID ptr;
  BYTE prio;
  static char queue[18];
  static HQUEUE qid = -1;
  char *ap, *ep, *p;
  char object[256] = {0};

  for ( cnt = 1, len = 0; args[cnt] != NULL; cnt++ )
    len += quoted_strlen(args[cnt]) + 1;
  p = ap = alloca(len + 2);
  *p = 0;
  for ( cnt = 1, len = 0; args[cnt] != NULL; cnt++ )
  {
    if ( cnt > 1 )
      *p++ = ' ';
    quoted_strcpy(p, args[cnt]);
    p += strlen(p);
  }
  for ( cnt = 0, len = 0; env[cnt] != NULL; cnt++ )
    len += strlen(env[cnt]) + 1;
  p = ep = alloca(len + 2);
  *p = 0;
  for ( cnt = 0, len = 0; env[cnt] != NULL; cnt++ )
  {
    strcpy(p, env[cnt]);
    p += strlen(p) + 1;
  }
  *p = 0;

  if ( mode == P_WAIT && qid == -1 )
  {
    sprintf(queue, "\\queues\\ksh%04d", getpid());
    if ( DosCreateQueue(&qid, QUE_FIFO, queue) )
      return -1;
  }

  sd.Length = sizeof(sd);
  sd.Related = (mode == P_WAIT) ? SSF_RELATED_CHILD : SSF_RELATED_INDEPENDENT;
  sd.FgBg = SSF_FGBG_FORE;
  sd.TraceOpt = SSF_TRACEOPT_NONE;
  sd.PgmTitle = NULL;
  sd.PgmName = cmd;
  sd.PgmInputs = (PBYTE) ap;
  sd.TermQ = (mode == P_WAIT) ? (PBYTE) queue : NULL;
  sd.Environment = NULL;
  sd.InheritOpt = SSF_INHERTOPT_PARENT;
  sd.SessionType = type;
  sd.IconFile = NULL;
  sd.PgmHandle = 0;
  sd.PgmControl = 0;
  sd.Reserved = 0;
  sd.ObjectBuffer = object;
  sd.ObjectBuffLen = sizeof(object);

  rc = DosStartSession(&sd, &sid, &pid);
  if (rc && rc != ERROR_SMG_START_IN_BACKGROUND)
    return errno = ENOEXEC, -1;

  if ( mode == P_WAIT )
  {
    STATUSDATA st;
    char *set_bond;
    char *window_hide;
    char *switch_entry_hide;		/* Window list */
    HSWITCH hSwitch = NULLHANDLE;
    SWCNTRL switchData;
    ULONG old_visibility;
    ULONG old_size = SWP_MINIMIZE;	/* By default, do nothing */

    /* Setting EXEC_PM_BOND=0 disables the bond between pdksh and 
       a PM application.  When the bond is active, chosing the pdksh window
       from the switch list (say, after Control-Esc) will actually choose the
       PM application. */
    set_bond = str_val(global("EXEC_PM_SET_BOND"));
    if (!set_bond || !*set_bond || atoi(set_bond)) {	/* Default on */
      st.Length = sizeof(st);
      st.SelectInd = SET_SESSION_UNCHANGED;
      st.BondInd = SET_SESSION_BOND;
      DosSetSession(sid, &st);
    }

    /* Setting EXEC_PM_WINDOW_HIDE=1 will hide the pdksh window while a
       kid PM application is running. */
    window_hide = str_val(global("EXEC_PM_WINDOW_HIDE"));
    if ( !( window_hide && *window_hide && atoi(window_hide) ) )
      window_hide = 0;

    /* Setting EXEC_PM_SWITCH_ENTRY_HIDE=1 will remove the pdksh entry
       from the switch list (shown on, say, Control-Esc) while a
       kid PM application is running. */
    switch_entry_hide = str_val(global("EXEC_PM_SWITCH_ENTRY_HIDE"));
    if (!(switch_entry_hide && *switch_entry_hide && atoi(switch_entry_hide)))
      switch_entry_hide = 0;
    if ( switch_entry_hide || window_hide )
      hSwitch = WinQuerySwitchHandle (NULLHANDLE, getpid ());
    if (hSwitch == NULLHANDLE)
      switch_entry_hide = window_hide = 0;
    else {
      rc = WinQuerySwitchEntry(hSwitch, &switchData);
      if (rc != 0)
        switch_entry_hide = window_hide = 0, hSwitch = NULLHANDLE;
    }
    if (switch_entry_hide) {
      old_visibility = switchData.uchVisibility;
      switchData.uchVisibility = SWL_INVISIBLE;
      rc = WinChangeSwitchEntry(hSwitch, &switchData);
      if (rc != 0)
	switch_entry_hide = 0;
    }
    if (window_hide) {
      SWP swp;

      rc = WinQueryWindowPos(switchData.hwnd, &swp);
      if (rc)
	old_size = (swp.fl & (SWP_MINIMIZE | SWP_MAXIMIZE | SWP_RESTORE));
    }
    if (old_size != SWP_MINIMIZE)
      WinPostMsg(switchData.hwnd, WM_SYSCOMMAND, MPFROMSHORT(SC_MINIMIZE), 0);

    rc = DosReadQueue(qid, &qr, &len, &ptr, 0, DCWW_WAIT, &prio, 0);

    if (switch_entry_hide) {		/* Restore */
      switchData.uchVisibility = old_visibility;
      WinChangeSwitchEntry(hSwitch, &switchData);
    }
    if (old_size != SWP_MINIMIZE)
      WinPostMsg(switchData.hwnd, WM_SYSCOMMAND,
		 MPFROMSHORT((old_size == SWP_RESTORE)
			     ? SC_RESTORE
			     : SC_MAXIMIZE), 0);
    if (rc)
      return -1;
    rc = ((PUSHORT)ptr)[1];
    DosFreeMem(ptr);
    exit(rc);
  }
  else
    exit(0);
}

#define CHECK_CONSECUTIVE_FDS	40	/* Hack to enumerate open fds */

/* EMX's execve()/spawnve(P_OVERLAY) are not waiting for the kid
   to end (unless after fork()), so our parent will get *our* exit code
   instead of the exec()ed program.
   The following code is an approximation to spawn_fork_exec() of EMX.
 */
static int
my_overlayve(int flag, char *path, char **args, char **env)
{
  int rc, pid, fd = -1, prev_fd = -1, status;

  pid = spawnve(P_NOWAIT | flag, path, args, env);
  if (pid <= 0)
    return -1;
  /* Close all the non-socket handles: closing sockets has severe side
     effects due to per-system semantic of sockets. */
  while (++fd <= prev_fd + CHECK_CONSECUTIVE_FDS) {
    struct stat buf;

    if (fstat(fd, &buf) < 0)
      continue;			/* Not an open filehandle */
    prev_fd = fd;
    if (!S_ISSOCK(buf.st_mode))
      close(fd);		/* Needed both for inheritable and others */
  }
  /* Remove the delayed TMP files which are open in the child */
  if (delayed_remove)
    remove_temps(0);
  while ((rc = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
    /* NOTHING */ ;
  /* Remove the remaining delayed TMP files */
  if (delayed_remove)
    remove_temps(0);
  if (rc < 0)
    return -1;
  _exit(status >> 8);
}

int ksh_execve(char *cmd, char **args, char **env, int flags)
{
  ULONG apptype;
  char path[256], *p;
  int rc, len = strlen(cmd);

  if ( len >= sizeof(path) ) {
     errno = ENAMETOOLONG;
     return -1;
  }
  strcpy(path, cmd);
  for ( p = path; *p; p++ )
    if ( *p == '/' )
      *p = '\\';

  if (!(flags & XSHARPBANG)		/* The extension was not appended */
      && !strrchr((p = ksh_strrchr_dirsep(path)) ? p : path, '.')) {
      /* Append dot, otherwise some suffix will be appended... */
      if ( len + 1 >= sizeof(path) ) {
         errno = ENAMETOOLONG;
         return -1;
      }
      path[len]     = '.';
      path[len + 1] = '\0';
  }
  if (_emx_env & 0x1000) {		/* RSX, do best we can do. */
      int len = strlen(cmd);

      if (len > 4 && stricmp(cmd + len - 4, ".bat") == 0) {
	  /* execve would fail anyway, but most probably segfault. */
	  errno = ENOEXEC;
	  return -1;
      }
      goto do_execve;
  }

  if ( inDOS() ) {
    fprintf(stderr, "ksh_execve requires OS/2 or RSX!\n");
    exit(255);
  }

  if ( DosQueryAppType(path, &apptype) == 0 )
  {	/* Start asyncroneously if run interactively and not a part of a pipeline */
    int force_async_flag;

    if (apptype & FAPPTYP_DOS)
      return newsession(isfullscreen() ? SSF_TYPE_VDM :
                                         SSF_TYPE_WINDOWEDVDM, 
			P_WAIT, path, args, env);

    if ((apptype & FAPPTYP_WINDOWSREAL) ||
        (apptype & FAPPTYP_WINDOWSPROT) ||
        (apptype & FAPPTYP_WINDOWSPROT31))
      return newsession(isfullscreen() ? PROG_WINDOW_AUTO :
                                         PROG_SEAMLESSCOMMON,
			P_WAIT, path, args, env);

    /* Setting EXEC_PM_ASYNC=1 enables async start of PM applicaitons
       from interactive shells when not a part of a pipeline; setting this
       may break things if a script checks for $? later. */
    force_async_flag = ((flags & XINTACT) && !(flags & XPIPE));
    if (force_async_flag) {
      char *user_async = str_val(global("EXEC_PM_ASYNC"));
      if ( !( user_async && *user_async && atoi(user_async) ) )
        force_async_flag = 0;
    }
    force_async_flag = (force_async_flag ? P_NOWAIT : P_WAIT);
    if ( (apptype & FAPPTYP_EXETYPE) == FAPPTYP_WINDOWAPI ) {
      printf(""); /* kludge to prevent PM apps from core dumping */
      /* Start new session if interactive and not a part of a pipe. */
      return newsession(SSF_TYPE_PM, force_async_flag,
			path, args, env);
    }

    if ( (apptype & FAPPTYP_EXETYPE) == FAPPTYP_NOTWINDOWCOMPAT ||
         (apptype & FAPPTYP_EXETYPE) == FAPPTYP_NOTSPEC )
      if ( !isfullscreen() )
        return newsession(SSF_TYPE_FULLSCREEN, force_async_flag,
			path, args, env);
  }
  do_execve:
  {
      /* P_QUOTE is too agressive, it quotes `@args_from_file' too,
	 which breaks emxomfld calling LINK386 when EMXSHELL=ksh.
	 Thus we check whether we need to quote, and delegate the hard
	 work to P_QUOTE if needed.  */
      char **pp = args;
      int do_quote = 0;

      for (; !do_quote && *pp; pp++) {
	  for (p = *pp; *p; p++) {
	      if (*p == '*' || *p == '?') {
		  do_quote = P_QUOTE;
		  break;
	      }
	  }
      }
      
      /* Work around EMX "optimization": unless exec-after-fork(),
	 our parent would get exit code 0 immediately on exec(). */
      if (!(flags & XFORKEXEC) || delayed_remove)	/* Returns on error only */
	return(my_overlayve(do_quote, path, args, env));
      rc = spawnve(P_OVERLAY | do_quote, path, args, env);
      if ( rc != -1 )
	  exit(rc);
  }
  return -1;
}

void UnixName(char *path)
{
  for ( ; *path; path++ )
    if ( *path == '\\' )
      *path = '/';
}

char *ksh_strchr_dirsep(const char *path)
{
  char *p1 = strchr(path, '\\');
  char *p2 = strchr(path, '/');
  if ( !p1 ) return p2;
  if ( !p2 ) return p1;
  return (p1 > p2) ? p2 : p1;
}


char *ksh_strrchr_dirsep(const char *path)
{
  char *p1 = strrchr(path, '\\');
  char *p2 = strrchr(path, '/');
  if ( !p1 ) return p2;
  if ( !p2 ) return p1;
  return (p1 > p2) ? p1 : p2;
}
