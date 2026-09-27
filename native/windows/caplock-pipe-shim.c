/*
 * CapLock's AppContainer compatibility preload for old libuv builds.
 *
 * libuv before 1.53 creates its private stdio pipes below \\?\pipe\uv\.
 * Windows permits an AppContainer to create only its LOCAL pipe namespace, so
 * Node's default child_process pipes otherwise block before CreateProcess.
 * This module patches only node.exe's imports for the three named-pipe APIs
 * and only rewrites that exact private libuv prefix.  It is intentionally not
 * a general filesystem or API hook.
 */
#include <windows.h>
#include <winnt.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>

/* Keep this a header-free N-API addon: Node resolves this exported registration
   function without linking node.lib, and the shim needs no JavaScript APIs. */
typedef void *napi_env;
typedef void *napi_value;

typedef HANDLE (WINAPI *CreateNamedPipeAFn)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI *CreateNamedPipeWFn)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI *CreateFileAFn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CreateFileWFn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WaitNamedPipeAFn)(LPCSTR, DWORD);
typedef BOOL (WINAPI *WaitNamedPipeWFn)(LPCWSTR, DWORD);

static CreateNamedPipeAFn original_create_named_pipe_a;
static CreateNamedPipeWFn original_create_named_pipe_w;
static CreateFileAFn original_create_file_a;
static CreateFileWFn original_create_file_w;
static WaitNamedPipeAFn original_wait_named_pipe_a;
static WaitNamedPipeWFn original_wait_named_pipe_w;
static volatile LONG shim_installed;
static volatile LONG pipe_sequence;

static BOOL diagnostics_enabled(void) {
  wchar_t enabled[2];
  return GetEnvironmentVariableW(L"CAPLOCK_PIPE_SHIM_DIAGNOSTIC", enabled, _countof(enabled)) != 0;
}

static void diagnostic_stage(const char *stage) {
  HANDLE file; DWORD written; char line[128];
  if (!diagnostics_enabled()) return;
  _snprintf_s(line, sizeof(line), _TRUNCATE, "%lu %s\r\n", (unsigned long)GetCurrentProcessId(), stage);
  file = CreateFileW(L"caplock-pipe-shim-stages.log", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { WriteFile(file, line, (DWORD)strlen(line), &written, NULL); CloseHandle(file); }
}

static void diagnostic_failure(const char *stage, DWORD error, const char *api) {
  HANDLE file; DWORD written; char line[192]; wchar_t image[MAX_PATH] = L""; char module[MAX_PATH] = ""; wchar_t *basename;
  if (!diagnostics_enabled()) return;
  GetModuleFileNameW(NULL, image, _countof(image)); basename = wcsrchr(image, L'\\'); WideCharToMultiByte(CP_UTF8, 0, basename ? basename + 1 : image, -1, module, sizeof(module), NULL, NULL);
  _snprintf_s(line, sizeof(line), _TRUNCATE, "%lu stage=%s error=%lu module=%s api=%s\r\n", (unsigned long)GetCurrentProcessId(), stage, (unsigned long)error, module[0] ? module : "<unknown>", api);
  file = CreateFileW(L"caplock-pipe-shim-errors.log", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { WriteFile(file, line, (DWORD)strlen(line), &written, NULL); CloseHandle(file); }
  fprintf(stderr, "CapLock pipe shim initialization failure: stage=%s error=%lu module=%s api=%s\n", stage, (unsigned long)error, module[0] ? module : "<unknown>", api);
}

static void diagnostic_marker(const wchar_t *name) {
  wchar_t enabled[2]; HANDLE file; DWORD written; char value[32];
  if (GetEnvironmentVariableW(L"CAPLOCK_PIPE_SHIM_DIAGNOSTIC", enabled, _countof(enabled)) == 0) return;
  _snprintf_s(value, sizeof(value), _TRUNCATE, "%lu\n", (unsigned long)GetCurrentProcessId());
  file = CreateFileW(name, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { WriteFile(file, value, (DWORD)strlen(value), &written, NULL); CloseHandle(file); }
}

static void diagnostic_pipe_call(const char *api, LPCSTR name, BOOL rewritten, BOOL succeeded, DWORD error) {
  char line[768]; HANDLE file; DWORD written;
  wchar_t enabled[2];
  if (GetEnvironmentVariableW(L"CAPLOCK_PIPE_SHIM_DIAGNOSTIC", enabled, _countof(enabled)) == 0 || name == NULL || _strnicmp(name, "\\\\?\\pipe\\uv\\", 12) != 0) return;
  _snprintf_s(line, sizeof(line), _TRUNCATE, "%s rewritten=%s succeeded=%s error=%lu name=%s\r\n", api, rewritten ? "true" : "false", succeeded ? "true" : "false", (unsigned long)error, name);
  file = CreateFileW(L"caplock-pipe-shim-paths.log", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { WriteFile(file, line, (DWORD)strlen(line), &written, NULL); CloseHandle(file); }
}

static BOOL pipe_belongs_to_current_process_a(LPCSTR name) {
  char *end; const char *suffix = strrchr(name, '-'); unsigned long pid;
  if (suffix == NULL || suffix[1] == '\0') return FALSE;
  pid = strtoul(suffix + 1, &end, 10);
  return *end == '\0' && pid == GetCurrentProcessId();
}

static BOOL pipe_belongs_to_current_process_w(LPCWSTR name) {
  wchar_t *end; const wchar_t *suffix = wcsrchr(name, L'-'); unsigned long pid;
  if (suffix == NULL || suffix[1] == L'\0') return FALSE;
  pid = wcstoul(suffix + 1, &end, 10);
  return *end == L'\0' && pid == GetCurrentProcessId();
}

static BOOL rewrite_pipe_a(LPCSTR source, char destination[512], BOOL require_current_process) {
  static const char *prefixes[] = { "\\\\?\\pipe\\uv\\", "\\\\.\\pipe\\uv\\" };
  if (source == NULL) return FALSE;
  for (size_t i = 0; i < _countof(prefixes); i++) {
    size_t prefix_length = strlen(prefixes[i]);
    if (_strnicmp(source, prefixes[i], prefix_length) == 0) {
      if (require_current_process && !pipe_belongs_to_current_process_a(source)) return FALSE;
      const char *suffix = source + prefix_length;
      return SUCCEEDED(StringCchPrintfA(destination, 512, "%.*sLOCAL\\uv\\%s", (int)(prefix_length - 3), prefixes[i], suffix));
    }
  }
  return FALSE;
}

static BOOL rewrite_pipe_w(LPCWSTR source, wchar_t destination[512], BOOL require_current_process) {
  static const wchar_t *prefixes[] = { L"\\\\?\\pipe\\uv\\", L"\\\\.\\pipe\\uv\\" };
  if (source == NULL) return FALSE;
  for (size_t i = 0; i < _countof(prefixes); i++) {
    size_t prefix_length = wcslen(prefixes[i]);
    if (_wcsnicmp(source, prefixes[i], prefix_length) == 0) {
      if (require_current_process && !pipe_belongs_to_current_process_w(source)) return FALSE;
      const wchar_t *suffix = source + prefix_length;
      return SUCCEEDED(StringCchPrintfW(destination, 512, L"%.*sLOCAL\\uv\\%s", (int)(prefix_length - 3), prefixes[i], suffix));
    }
  }
  return FALSE;
}

/* libuv records the generated pipe name and uses it again when handing the
   client endpoint to the nested process. Its stdio helper starts that name
   from INVALID_HANDLE_VALUE (-1), so make the mutable libuv buffer unique
   before it is recorded rather than remapping only individual Win32 calls. */
static BOOL uniquify_pipe_server_a(LPCSTR source) {
  char replacement[512]; char *mutable_name = (char *)source; const char *slash, *dash; size_t prefix;
  if (!pipe_belongs_to_current_process_a(source)) return FALSE;
  slash = strrchr(source, '\\'); dash = strrchr(source, '-');
  if (slash == NULL || dash == NULL || dash <= slash) return FALSE;
  prefix = (size_t)(slash - source + 1);
  if (FAILED(StringCchPrintfA(replacement, _countof(replacement), "%.*s%lu-%lu", (int)prefix, source, (unsigned long)InterlockedIncrement(&pipe_sequence), (unsigned long)GetCurrentProcessId()))) return FALSE;
  if (strlen(replacement) > strlen(source)) return FALSE;
  CopyMemory(mutable_name, replacement, strlen(replacement) + 1);
  return TRUE;
}
static BOOL uniquify_pipe_server_w(LPCWSTR source) {
  wchar_t replacement[512]; wchar_t *mutable_name = (wchar_t *)source; const wchar_t *slash, *dash; size_t prefix;
  if (!pipe_belongs_to_current_process_w(source)) return FALSE;
  slash = wcsrchr(source, L'\\'); dash = wcsrchr(source, L'-');
  if (slash == NULL || dash == NULL || dash <= slash) return FALSE;
  prefix = (size_t)(slash - source + 1);
  if (FAILED(StringCchPrintfW(replacement, _countof(replacement), L"%.*s%lu-%lu", (int)prefix, source, (unsigned long)InterlockedIncrement(&pipe_sequence), (unsigned long)GetCurrentProcessId()))) return FALSE;
  if (wcslen(replacement) > wcslen(source)) return FALSE;
  CopyMemory(mutable_name, replacement, (wcslen(replacement) + 1) * sizeof(wchar_t));
  return TRUE;
}

static HANDLE WINAPI shim_create_named_pipe_a(LPCSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_size, DWORD in_size, DWORD timeout, LPSECURITY_ATTRIBUTES security) {
  char replacement[512]; uniquify_pipe_server_a(name); BOOL rewritten = rewrite_pipe_a(name, replacement, FALSE);
  HANDLE result = original_create_named_pipe_a(rewritten ? replacement : name, open_mode, pipe_mode, max_instances, out_size, in_size, timeout, security); diagnostic_pipe_call("CreateNamedPipeA", name, rewritten, result != INVALID_HANDLE_VALUE, result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS);
  return result;
}
static HANDLE WINAPI shim_create_named_pipe_w(LPCWSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_size, DWORD in_size, DWORD timeout, LPSECURITY_ATTRIBUTES security) {
  wchar_t replacement[512]; uniquify_pipe_server_w(name); BOOL rewritten = rewrite_pipe_w(name, replacement, FALSE);
  return original_create_named_pipe_w(rewritten ? replacement : name, open_mode, pipe_mode, max_instances, out_size, in_size, timeout, security);
}
static HANDLE WINAPI shim_create_file_a(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD creation, DWORD flags, HANDLE template_file) {
  char replacement[512]; BOOL rewritten = rewrite_pipe_a(name, replacement, TRUE); HANDLE result = original_create_file_a(rewritten ? replacement : name, access, share, security, creation, flags, template_file); diagnostic_pipe_call("CreateFileA", name, rewritten, result != INVALID_HANDLE_VALUE, result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS);
  return result;
}
static HANDLE WINAPI shim_create_file_w(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD creation, DWORD flags, HANDLE template_file) {
  wchar_t replacement[512];
  return original_create_file_w(rewrite_pipe_w(name, replacement, TRUE) ? replacement : name, access, share, security, creation, flags, template_file);
}
static BOOL WINAPI shim_wait_named_pipe_a(LPCSTR name, DWORD timeout) { char replacement[512]; return original_wait_named_pipe_a(rewrite_pipe_a(name, replacement, TRUE) ? replacement : name, timeout); }
static BOOL WINAPI shim_wait_named_pipe_w(LPCWSTR name, DWORD timeout) { wchar_t replacement[512]; return original_wait_named_pipe_w(rewrite_pipe_w(name, replacement, TRUE) ? replacement : name, timeout); }

static BOOL is_appcontainer(void) {
  HANDLE token; DWORD value = 0, size = sizeof(value);
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
  BOOL ok = GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &size) && value != 0;
  CloseHandle(token); return ok;
}

/* The helper verifies TokenIsAppContainer on the exact suspended process
   before it is resumed. Some Node Windows startup paths expose a restricted
   process token to an addon query even though the launcher verification has
   already succeeded. CAPLOCK_PIPE_SHIM_FORCE is injected only by that trusted
   launcher into the private lifecycle environment; it is not ambient input. */
static BOOL trusted_launcher_authorized(void) {
  wchar_t value[32] = L"", *end = NULL; unsigned long root_pid;
  if (GetEnvironmentVariableW(L"CAPLOCK_PIPE_SHIM_FORCE", value, _countof(value)) != 1 || value[0] != L'1') return FALSE;
  if (GetEnvironmentVariableW(L"CAPLOCK_PIPE_SHIM_ROOT_PID", value, _countof(value)) == 0) return FALSE;
  root_pid = wcstoul(value, &end, 10);
  return end != value && *end == L'\0' && root_pid == GetCurrentProcessId();
}

static FARPROC replacement_for(const char *name, FARPROC current) {
  if (strcmp(name, "CreateNamedPipeA") == 0) { original_create_named_pipe_a = (CreateNamedPipeAFn)current; return (FARPROC)shim_create_named_pipe_a; }
  if (strcmp(name, "CreateNamedPipeW") == 0) { original_create_named_pipe_w = (CreateNamedPipeWFn)current; return (FARPROC)shim_create_named_pipe_w; }
  if (strcmp(name, "CreateFileA") == 0) { original_create_file_a = (CreateFileAFn)current; return (FARPROC)shim_create_file_a; }
  if (strcmp(name, "CreateFileW") == 0) { original_create_file_w = (CreateFileWFn)current; return (FARPROC)shim_create_file_w; }
  if (strcmp(name, "WaitNamedPipeA") == 0) { original_wait_named_pipe_a = (WaitNamedPipeAFn)current; return (FARPROC)shim_wait_named_pipe_a; }
  if (strcmp(name, "WaitNamedPipeW") == 0) { original_wait_named_pipe_w = (WaitNamedPipeWFn)current; return (FARPROC)shim_wait_named_pipe_w; }
  return NULL;
}

static BOOL install_node_import_hooks(void) {
  HMODULE module = GetModuleHandleW(NULL);
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
  diagnostic_stage("shim.module-enumeration-start");
  if (module == NULL) { diagnostic_failure("shim.module-found", GetLastError(), "GetModuleHandleW"); return FALSE; }
  diagnostic_stage("shim.module-enumeration-complete");
  diagnostic_stage("shim.module-found");
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) { diagnostic_failure("shim.module-found", ERROR_BAD_EXE_FORMAT, "IMAGE_DOS_HEADER"); return FALSE; }
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)module + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { diagnostic_failure("shim.module-found", ERROR_BAD_EXE_FORMAT, "IMAGE_NT_HEADERS"); return FALSE; }
  IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (directory.VirtualAddress == 0 || directory.Size == 0) { diagnostic_failure("shim.import-table-start", ERROR_PROC_NOT_FOUND, "IMAGE_DIRECTORY_ENTRY_IMPORT"); return FALSE; }
  IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)module + directory.VirtualAddress);
  BOOL saw_pipe_create = FALSE, saw_pipe_open = FALSE;
  diagnostic_stage("shim.iat-scan-start");
  for (; imports->Name != 0; imports++) {
    IMAGE_THUNK_DATA64 *names = (IMAGE_THUNK_DATA64 *)((BYTE *)module + imports->OriginalFirstThunk);
    IMAGE_THUNK_DATA64 *addresses = (IMAGE_THUNK_DATA64 *)((BYTE *)module + imports->FirstThunk);
    { char module_name[128]; const char *name = (const char *)module + imports->Name; _snprintf_s(module_name, sizeof(module_name), _TRUNCATE, "shim.iat-scan-module:%s", strrchr(name, '\\') ? strrchr(name, '\\') + 1 : name); diagnostic_stage(module_name); }
    if (imports->OriginalFirstThunk == 0 || imports->FirstThunk == 0) { diagnostic_failure("shim.import-table-start", ERROR_BAD_EXE_FORMAT, "IMAGE_THUNK_DATA"); return FALSE; }
    for (; names->u1.AddressOfData != 0; names++, addresses++) {
      if (IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal)) continue;
      IMAGE_IMPORT_BY_NAME *entry = (IMAGE_IMPORT_BY_NAME *)((BYTE *)module + names->u1.AddressOfData);
      FARPROC replacement = replacement_for((const char *)entry->Name, (FARPROC)(ULONG_PTR)addresses->u1.Function);
      if (replacement == NULL) continue;
      if (strcmp((const char *)entry->Name, "CreateNamedPipeA") == 0) { saw_pipe_create = TRUE; diagnostic_stage("shim.iat-patch-CreateNamedPipeA"); }
      if (strcmp((const char *)entry->Name, "CreateNamedPipeW") == 0) saw_pipe_create = TRUE;
      if (strcmp((const char *)entry->Name, "CreateFileA") == 0) { saw_pipe_open = TRUE; diagnostic_stage("shim.iat-patch-CreateFileA"); }
      if (strcmp((const char *)entry->Name, "CreateFileW") == 0) saw_pipe_open = TRUE;
      DWORD old_protect;
      diagnostic_stage("shim.patch-start");
      diagnostic_stage("shim.protection-change-start");
      if (!VirtualProtect(&addresses->u1.Function, sizeof(addresses->u1.Function), PAGE_READWRITE, &old_protect)) { diagnostic_failure("shim.patch-start", GetLastError(), (const char *)entry->Name); return FALSE; }
      InterlockedExchangePointer((PVOID volatile *)&addresses->u1.Function, (PVOID)replacement);
      DWORD ignored;
      if (!VirtualProtect(&addresses->u1.Function, sizeof(addresses->u1.Function), old_protect, &ignored)) { diagnostic_failure("shim.patch-complete", GetLastError(), (const char *)entry->Name); return FALSE; }
      diagnostic_stage("shim.protection-change-complete");
      FlushInstructionCache(GetCurrentProcess(), &addresses->u1.Function, sizeof(addresses->u1.Function));
      diagnostic_stage("shim.cache-flush-complete");
      diagnostic_stage("shim.patch-complete");
    }
  }
  if (!saw_pipe_create || !saw_pipe_open || !(original_create_named_pipe_a || original_create_named_pipe_w) || !(original_create_file_a || original_create_file_w)) { diagnostic_failure("shim.import-table-start", ERROR_PROC_NOT_FOUND, "required-import"); return FALSE; }
  return TRUE;
}

__declspec(dllexport) napi_value napi_register_module_v1(napi_env env, napi_value exports) {
  (void)env;
  diagnostic_marker(L"caplock-pipe-shim-entered.marker");
  diagnostic_stage("shim.entry");
  diagnostic_stage("shim.appcontainer-check-start");
  if (!is_appcontainer() && !trusted_launcher_authorized()) { diagnostic_stage("shim.appcontainer-check-complete"); diagnostic_failure("shim.appcontainer-detected", ERROR_ACCESS_DENIED, "TokenIsAppContainer"); return exports; }
  diagnostic_stage("shim.appcontainer-check-complete");
  diagnostic_stage("shim.appcontainer-detected");
  if (InterlockedCompareExchange(&shim_installed, 1, 0) == 0 && !install_node_import_hooks()) {
    /* A failed hook must never leave a partially trusted process running. */
    TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
  }
  diagnostic_stage("shim.install-complete");
  diagnostic_marker(L"caplock-pipe-shim-installed.marker");
  return exports;
}
