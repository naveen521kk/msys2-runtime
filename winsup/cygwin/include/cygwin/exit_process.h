#ifndef EXIT_PROCESS_H
#define EXIT_PROCESS_H

#include <stdio.h>

/*
 * This file contains functions to terminate a Win32 process, as gently as
 * possible.
 *
 * If appropriate, we will attempt to emulate a console Ctrl event for the
 * process. Otherwise we will fall back to terminating the process.
 *
 * As we do not want to export this function in the MSYS2 runtime, these
 * functions are marked as file-local.
 *
 * The idea is to inject a thread into the given process that runs either
 * kernel32!CtrlRoutine() (i.e. the work horse of GenerateConsoleCtrlEvent())
 * for SIGINT (Ctrl+C) and SIGQUIT (Ctrl+Break), or ExitProcess() for SIGTERM.
 * This is handled through the console helpers.
 *
 * For SIGKILL, we run TerminateProcess() without injecting anything, and this
 * is also the fall-back when the previous methods are unavailable.
 *
 * Note: as kernel32.dll is loaded before any process, the other process and
 * this process will have ExitProcess() at the same address. The same holds
 * true for kernel32!CtrlRoutine(), of course, but it is an internal API
 * function, so we cannot look it up directly. Instead, we launch
 * getprocaddr.exe to find out and inject the remote thread.
 *
 * This function expects the process handle to have the access rights for
 * CreateRemoteThread(): PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
 * PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ.
 *
 * The idea for the injected remote thread comes from the Dr Dobb's article "A
 * Safer Alternative to TerminateProcess()" by Andrew Tucker (July 1, 1999),
 * http://www.drdobbs.com/a-safer-alternative-to-terminateprocess/184416547.
 *
 * The idea to use kernel32!CtrlRoutine for the other signals comes from
 * SendSignal (https://github.com/AutoSQA/SendSignal/ and
 * http://stanislavs.org/stopping-command-line-applications-programatically-with-ctrl-c-events-from-net/).
 */

#include <math.h>
#include <wchar.h>

#ifndef __INSIDE_CYGWIN__
/* To help debugging via kill.exe */
#define small_printf(...) fprintf (stderr, __VA_ARGS__)
#endif

static BOOL get_wow (HANDLE process, BOOL &is_wow, int &bitness);
static int exit_process_tree (HANDLE main_process, int exit_code);

static BOOL
kill_via_console_helper (HANDLE process, wchar_t *function_name, int exit_code,
                         DWORD pid)
{
  BOOL is_wow;
  int bitness;
  if (!get_wow (process, is_wow, bitness))
    {
      return FALSE;
    }

  const char *name;
  if (bitness == 32)
    name = "/usr/libexec/getprocaddr32.exe";
  else if (bitness == 64)
    name = "/usr/libexec/getprocaddr64.exe";
  else
    return NULL; /* what?!? */
  wchar_t wbuf[PATH_MAX];

  if (cygwin_conv_path (CCP_POSIX_TO_WIN_W, name, wbuf, PATH_MAX)
      || GetFileAttributesW (wbuf) == INVALID_FILE_ATTRIBUTES)
    return NULL;

  STARTUPINFOW si = {};
  PROCESS_INFORMATION pi;
  size_t len = wcslen (wbuf) + wcslen (function_name) + 3 /* exit code */
               + 1 /* space */ + 10 /* process ID, i.e. DWORD */ + 1 /* NUL */;
  WCHAR cmd[len + 1];
  WCHAR title[] = L"cygwin-console-helper";
  DWORD process_exit;

  swprintf (cmd, len + 1, L"%S %S %d %ld", wbuf, function_name, exit_code,
            pid);
  
  printf("%s", cmd);
  
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.lpTitle = title;
  si.hStdInput = si.hStdError = si.hStdOutput = INVALID_HANDLE_VALUE;

  /* Create a new hidden process. */
  if (!CreateProcessW (NULL, cmd, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL,
                       &si, &pi))
    {
      return FALSE;
    }
  else
    {
      /* Wait for the process to complete for 10 seconds */
      WaitForSingleObject (pi.hProcess, 10000);
    }

  if (!GetExitCodeProcess (pi.hProcess, &process_exit))
    process_exit = -1;

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  return process_exit == 0 ? TRUE : FALSE;
}

static int current_is_wow = -1;
static int is_32_bit_os = -1;

static BOOL
get_wow (HANDLE process, BOOL &is_wow, int &bitness)
{
  if (is_32_bit_os == -1)
    {
      SYSTEM_INFO info;

      GetNativeSystemInfo (&info);
      if (info.wProcessorArchitecture == 0)
        is_32_bit_os = 1;
      else if (info.wProcessorArchitecture == 9)
        is_32_bit_os = 0;
      else
        is_32_bit_os = -2;
    }

  if (current_is_wow == -1
      && !IsWow64Process (GetCurrentProcess (), &current_is_wow))
    current_is_wow = -2;

  if (is_32_bit_os == -2 || current_is_wow == -2)
    return FALSE;

  if (!IsWow64Process (process, &is_wow))
    return FALSE;

  bitness = is_32_bit_os || is_wow ? 32 : 64;
  return TRUE;
}

/**
 * Terminates the process corresponding to the process ID
 *
 * This way of terminating the processes is not gentle: the process gets
 * no chance of cleaning up after itself (closing file handles, removing
 * .lock files, terminating spawned processes (if any), etc).
 */
static int
exit_process (HANDLE process, int exit_code)
{
  LPTHREAD_START_ROUTINE address = NULL;
  DWORD pid = GetProcessId (process), code;
  printf("%ld",pid);
  int signo = exit_code & 0x7f;
  switch (signo)
    {
    case SIGINT:
    case SIGQUIT:
      if (kill_via_console_helper (
              process, L"CtrlRoutine",
              signo == SIGINT ? CTRL_C_EVENT : CTRL_BREAK_EVENT, pid) &&
          GetExitCodeProcess(process, &code) && code != STILL_ACTIVE)
        return 0;
      /* fall-through */
    case SIGTERM:
      if (kill_via_console_helper (process, L"ExitProcess", exit_code, pid))
        return 0;
      break;
    default:
      break;
    }

  return int (TerminateProcess (process, exit_code));
}

#include <tlhelp32.h>
#include <unistd.h>

/**
 * Terminates the process corresponding to the process ID and all of its
 * directly and indirectly spawned subprocesses using the
 * TerminateProcess() function.
 */
static int
exit_process_tree (HANDLE main_process, int exit_code)
{
  HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 entry;
  DWORD pids[16384];
  int max_len = sizeof (pids) / sizeof (*pids), i, len, ret = 0;
  pid_t pid = GetProcessId (main_process);
  int signo = exit_code & 0x7f;

  pids[0] = (DWORD)pid;
  len = 1;

  /*
   * Even if Process32First()/Process32Next() seem to traverse the
   * processes in topological order (i.e. parent processes before
   * child processes), there is nothing in the Win32 API documentation
   * suggesting that this is guaranteed.
   *
   * Therefore, run through them at least twice and stop when no more
   * process IDs were added to the list.
   */
  for (;;)
    {
      memset (&entry, 0, sizeof (entry));
      entry.dwSize = sizeof (entry);

      if (!Process32First (snapshot, &entry))
        break;

      int orig_len = len;
      do
        {
          /**
           * Look for the parent process ID in the list of pids to kill, and if
           * found, add it to the list.
           */
          for (i = len - 1; i >= 0; i--)
            {
              if (pids[i] == entry.th32ProcessID)
                break;
              if (pids[i] != entry.th32ParentProcessID)
                continue;

              /* We found a process to kill; is it an MSYS2 process? */
              pid_t cyg_pid = cygwin_winpid_to_pid (entry.th32ProcessID);
              if (cyg_pid > -1)
                {
                  if (cyg_pid == getpgid (cyg_pid))
                    kill (cyg_pid, signo);
                  break;
                }
              pids[len++] = entry.th32ProcessID;
              break;
            }
        }
      while (len < max_len && Process32Next (snapshot, &entry));

      if (orig_len == len || len >= max_len)
        break;
    }

  for (i = len - 1; i >= 0; i--)
    {
      HANDLE process;

      if (!i)
        process = main_process;
      else
        {
          process = OpenProcess (
              PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                  | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
              FALSE, pids[i]);
          if (!process)
            process = OpenProcess (PROCESS_TERMINATE, FALSE, pids[i]);
        }
      DWORD code;

      if (process
          && (!GetExitCodeProcess (process, &code) || code == STILL_ACTIVE))
        {
          if (!exit_process (process, exit_code))
            ret = -1;
        }
      if (process)
        CloseHandle (process);
    }

  return ret;
}

#endif
