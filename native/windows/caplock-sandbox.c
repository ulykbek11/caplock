/* CapLock Windows sandbox helper. All security enforcement is native Win32. */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>

#define MAX_GRANTS 64

int wmain(int argc, wchar_t **argv);

typedef struct SavedAcl {
  const wchar_t *path;
  PSID sid;
} SavedAcl;

/* These are only populated while --selftest calls the normal launcher. */
typedef struct SelftestStatus {
  BOOL profileCreated, processLaunched, tokenIsAppContainer;
  BOOL parentExited, jobClean, watchdogFired, nodeChildObserved;
  DWORD childExitCode;
} SelftestStatus;
static SelftestStatus selftest_status = { 0 };
static BOOL selftest_running = FALSE;

static void print_last_error(const wchar_t *where) {
  DWORD error = GetLastError(); wchar_t *message = NULL;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, error, 0, (LPWSTR)&message, 0, NULL);
  fwprintf(stderr, L"caplock-sandbox: %ls failed (%lu): %ls\n", where, error, message == NULL ? L"unknown error" : message);
  if (message != NULL) LocalFree(message);
}

static BOOL debug_enabled(void) { return GetEnvironmentVariableW(L"CAPLOCK_DEBUG", NULL, 0) != 0; }

static void debug_control_context(const wchar_t *network) {
  static const wchar_t *names[] = { L"USERPROFILE", L"LOCALAPPDATA", L"APPDATA", L"SystemRoot", L"WINDIR", L"TEMP", L"TMP", L"ComSpec", L"PATH" };
  wchar_t module[MAX_PATH] = L"", *sid_text = NULL; DWORD session = 0, size = 0; HANDLE token = NULL; TOKEN_USER *user = NULL;
  if (!debug_enabled()) return;
  fwprintf(stderr, L"CapLock helper control context: inherited=true network=%ls creationFlags=0x%08lX\n", network, (unsigned long)(EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT));
  for (size_t i = 0; i < _countof(names); i++) fwprintf(stderr, L"CapLock helper control env: %ls=%ls\n", names[i], GetEnvironmentVariableW(names[i], NULL, 0) ? L"present" : L"absent");
  GetModuleFileNameW(NULL, module, _countof(module)); ProcessIdToSessionId(GetCurrentProcessId(), &session);
  fwprintf(stderr, L"CapLock helper control process: session=%lu helper=%ls\n", session, module);
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    GetTokenInformation(token, TokenUser, NULL, 0, &size); user = (TOKEN_USER *)LocalAlloc(LPTR, size);
    if (user != NULL && GetTokenInformation(token, TokenUser, user, size, &size) && ConvertSidToStringSidW(user->User.Sid, &sid_text)) fwprintf(stderr, L"CapLock helper control userSid=%ls\n", sid_text);
  }
  if (sid_text != NULL) LocalFree(sid_text); if (user != NULL) LocalFree(user); if (token != NULL) CloseHandle(token);
}

static BOOL grant_appcontainer_access(const wchar_t *path, PSID sid, DWORD access, SavedAcl *saved) {
  DWORD status;
  EXPLICIT_ACCESSW entry;
  PACL replacement = NULL;
  ZeroMemory(saved, sizeof(*saved));
  if (debug_enabled()) fwprintf(stderr, L"CapLock ACL target: %ls access=0x%08lX\n", path, (unsigned long)access);
  PACL dacl = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
  status = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    NULL, NULL, &dacl, NULL, &descriptor);
  if (status != ERROR_SUCCESS) { SetLastError(status); print_last_error(L"GetNamedSecurityInfoW"); return FALSE; }
  ZeroMemory(&entry, sizeof(entry));
  entry.grfAccessPermissions = access;
  entry.grfAccessMode = GRANT_ACCESS;
  entry.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entry.Trustee.ptstrName = (LPWSTR)sid;
  status = SetEntriesInAclW(1, &entry, dacl, &replacement);
  if (status != ERROR_SUCCESS) { LocalFree(descriptor); SetLastError(status); print_last_error(L"SetEntriesInAclW"); return FALSE; }
  status = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
    NULL, NULL, replacement, NULL);
  LocalFree(replacement);
  LocalFree(descriptor);
  if (status != ERROR_SUCCESS) { SetLastError(status); print_last_error(L"SetNamedSecurityInfoW"); return FALSE; }
  saved->path = path;
  saved->sid = sid;
  return TRUE;
}

static void restore_acl(SavedAcl *saved) {
  /* Remove only this run's unique SID ACE. Restoring an old DACL would race
     concurrent CapLock runs that granted their own unique AppContainer SIDs. */
  if (saved->path != NULL && saved->sid != NULL) {
    PACL dacl = NULL, replacement = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
    EXPLICIT_ACCESSW entry; DWORD status = GetNamedSecurityInfoW((LPWSTR)saved->path,
      SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &descriptor);
    if (status == ERROR_SUCCESS) {
      ZeroMemory(&entry, sizeof(entry)); entry.grfAccessMode = REVOKE_ACCESS;
      entry.Trustee.TrusteeForm = TRUSTEE_IS_SID; entry.Trustee.ptstrName = (LPWSTR)saved->sid;
      if (SetEntriesInAclW(1, &entry, dacl, &replacement) == ERROR_SUCCESS) {
        SetNamedSecurityInfoW((LPWSTR)saved->path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
          NULL, NULL, replacement, NULL);
        LocalFree(replacement);
      }
    }
    if (descriptor != NULL) LocalFree(descriptor);
  }
}

static BOOL append_argument(wchar_t *target, size_t capacity, const wchar_t *argument) {
  size_t length = wcslen(target), index = 0, slashes = 0;
  if (length + 3 >= capacity) return FALSE;
  if (length != 0) target[length++] = L' ';
  target[length++] = L'\"'; target[length] = L'\0';
  while (argument[index] != L'\0') {
    if (argument[index] == L'\\') { slashes++; index++; continue; }
    while (slashes > 0) { if (length + 1 >= capacity) return FALSE; target[length++] = L'\\'; slashes--; }
    if (argument[index] == L'\"') { if (length + 2 >= capacity) return FALSE; target[length++] = L'\\'; target[length++] = L'\"'; }
    else { if (length + 1 >= capacity) return FALSE; target[length++] = argument[index]; }
    index++;
  }
  while (slashes > 0) { if (length + 2 >= capacity) return FALSE; target[length++] = L'\\'; target[length++] = L'\\'; slashes--; }
  if (length + 2 >= capacity) return FALSE;
  target[length++] = L'\"'; target[length] = L'\0';
  return TRUE;
}

static BOOL child_is_appcontainer(HANDLE process) {
  HANDLE token = NULL; DWORD is_appcontainer = 0, size = sizeof(is_appcontainer);
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) { print_last_error(L"OpenProcessToken"); return FALSE; }
  if (!GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer, sizeof(is_appcontainer), &size)) { CloseHandle(token); print_last_error(L"GetTokenInformation(TokenIsAppContainer)"); return FALSE; }
  CloseHandle(token); return is_appcontainer != 0;
}

/* The helper keeps its inherited trusted control environment. This UTF-16LE
   block is used exclusively for the untrusted AppContainer child. */
static LPWCH read_child_environment(const wchar_t *path) {
  HANDLE file = INVALID_HANDLE_VALUE; LARGE_INTEGER size; DWORD read = 0;
  LPWCH block = NULL;
  file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) { print_last_error(L"CreateFileW environment"); return NULL; }
  if (!GetFileSizeEx(file, &size) || size.QuadPart < 4 || size.QuadPart > 1024 * 1024 || (size.QuadPart % sizeof(wchar_t)) != 0) { CloseHandle(file); fwprintf(stderr, L"caplock-sandbox: invalid child environment file\n"); return NULL; }
  block = (LPWCH)VirtualAlloc(NULL, (SIZE_T)size.QuadPart + 2 * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (block == NULL || !ReadFile(file, block, (DWORD)size.QuadPart, &read, NULL) || read != (DWORD)size.QuadPart) { if (block != NULL) VirtualFree(block, 0, MEM_RELEASE); CloseHandle(file); print_last_error(L"ReadFile environment"); return NULL; }
  CloseHandle(file);
  if (block[(size.QuadPart / sizeof(wchar_t)) - 1] != L'\0' || block[(size.QuadPart / sizeof(wchar_t)) - 2] != L'\0') { VirtualFree(block, 0, MEM_RELEASE); fwprintf(stderr, L"caplock-sandbox: invalid child environment terminator\n"); return NULL; }
  return block;
}

static void debug_child_environment(LPWCH block, SIZE_T bytes) {
  static const wchar_t *wanted[] = { L"SystemRoot", L"WINDIR", L"ComSpec", L"PATH", L"PATHEXT", L"TEMP", L"TMP", L"USERPROFILE", L"HOME", L"HOMEDRIVE", L"HOMEPATH", L"LOCALAPPDATA", L"APPDATA", L"NODE_OPTIONS", L"NODE_CHANNEL_FD", L"NODE_UNIQUE_ID" };
  SIZE_T index = 0, count = 0, chars = bytes / sizeof(wchar_t); BOOL well_formed = TRUE, sorted = TRUE; const wchar_t *previous = NULL;
  if (!debug_enabled()) return;
  while (index + 1 < chars && block[index] != L'\0') { wchar_t *entry = block + index, *equals = wcschr(entry, L'='); if (equals == NULL || equals == entry) well_formed = FALSE; if (previous != NULL && _wcsicmp(previous, entry) > 0) sorted = FALSE; previous = entry; count++; index += wcslen(entry) + 1; }
  fwprintf(stderr, L"CapLock child environment block: mode=custom entries=%zu chars=%zu doubleNul=%s validEntries=%s sortedCaseInsensitive=%s\n", count, chars, (chars >= 2 && block[chars - 1] == L'\0' && block[chars - 2] == L'\0') ? L"true" : L"false", well_formed ? L"true" : L"false", sorted ? L"true" : L"false");
  for (SIZE_T w = 0; w < _countof(wanted); w++) { BOOL found = FALSE; index = 0; while (index < chars && block[index] != L'\0') { size_t n = wcslen(wanted[w]); if (_wcsnicmp(block + index, wanted[w], n) == 0 && block[index + n] == L'=') { found = TRUE; break; } index += wcslen(block + index) + 1; } fwprintf(stderr, L"CapLock child environment: %ls=%ls\n", wanted[w], found ? L"present" : L"absent"); }
}

static void debug_launch_request(const wchar_t *application, const wchar_t *cwd, BOOL environment_inherited) {
  static const wchar_t *required[] = { L"SystemRoot", L"WINDIR", L"ComSpec", L"PATH", L"PATHEXT", L"TEMP", L"TMP", L"HOME", L"USERPROFILE" };
  if (!debug_enabled()) return;
  fwprintf(stderr, L"CapLock AppContainer CreateProcessW: application=%ls cwd=%ls environment=%ls\n", application, cwd, environment_inherited ? L"inherited" : L"custom");
  if (environment_inherited) for (size_t i = 0; i < _countof(required); i++) fwprintf(stderr, L"CapLock AppContainer environment: %ls=%ls\n", required[i], GetEnvironmentVariableW(required[i], NULL, 0) ? L"present" : L"absent");
}

static void debug_job_processes(HANDLE job) {
  BYTE storage[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 31 * sizeof(ULONG_PTR)];
  JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)storage;
  DWORD returned = 0;
  if (!debug_enabled() || !QueryInformationJobObject(job, JobObjectBasicProcessIdList, list, sizeof(storage), &returned)) return;
  for (ULONG_PTR i = 0; i < list->NumberOfProcessIdsInList; i++) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, (DWORD)list->ProcessIdList[i]);
    DWORD code = STILL_ACTIVE, handles = 0; wchar_t image[MAX_PATH] = L""; DWORD image_length = _countof(image);
    if (process != NULL) {
      GetExitCodeProcess(process, &code); GetProcessHandleCount(process, &handles); QueryFullProcessImageNameW(process, 0, image, &image_length); CloseHandle(process);
    }
    fwprintf(stderr, L"CapLock debug job process: pid=%lu state=%ls handles=%lu image=%ls\n", (unsigned long)list->ProcessIdList[i], code == STILL_ACTIVE ? L"active" : L"exited", (unsigned long)handles, image[0] ? image : L"<unavailable>");
  }
}

/* Never pass the helper's complete inheritable-handle set to untrusted code.
   In particular, an inherited pipe write end can keep a host-side reader open
   across a nested libuv spawn. The AppContainer child receives only private
   duplicates of its standard streams; the explicit handle list is also the
   boundary used by CreateProcess for all other inherited handles. */
static BOOL duplicate_standard_handles(HANDLE handles[3]) {
  const DWORD ids[3] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
  for (int i = 0; i < 3; i++) {
    HANDLE source = GetStdHandle(ids[i]); handles[i] = NULL;
    if (source == NULL || source == INVALID_HANDLE_VALUE ||
        !DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &handles[i], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
      print_last_error(L"DuplicateHandle standard stream");
      for (int j = 0; j < i; j++) { CloseHandle(handles[j]); handles[j] = NULL; }
      return FALSE;
    }
  }
  return TRUE;
}

static BOOL open_null_standard_handles(HANDLE handles[3]) {
  SECURITY_ATTRIBUTES security; ZeroMemory(&security, sizeof(security)); security.nLength = sizeof(security); security.bInheritHandle = TRUE;
  handles[0] = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  handles[1] = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  handles[2] = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (handles[0] == INVALID_HANDLE_VALUE || handles[1] == INVALID_HANDLE_VALUE || handles[2] == INVALID_HANDLE_VALUE) { print_last_error(L"CreateFileW NUL standard stream"); for (int i = 0; i < 3; i++) if (handles[i] != NULL && handles[i] != INVALID_HANDLE_VALUE) CloseHandle(handles[i]); return FALSE; }
  return TRUE;
}

/* These small modes are intentionally shell-free. They are used only as the
   child of the production AppContainer launcher in selftests and doctor. */
static int probe_write(const wchar_t *marker) {
  HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD written = 0; const char contents[] = "caplock-probe\n";
  if (file == INVALID_HANDLE_VALUE) { print_last_error(L"probe CreateFileW"); return 20; }
  if (!WriteFile(file, contents, (DWORD)(sizeof(contents) - 1), &written, NULL) || written != sizeof(contents) - 1) { print_last_error(L"probe WriteFile"); CloseHandle(file); return 21; }
  CloseHandle(file); return 0;
}

static BOOL equal_windows_path(const wchar_t *left, const wchar_t *right) {
  wchar_t a[MAX_PATH], b[MAX_PATH];
  DWORD al = GetFullPathNameW(left, _countof(a), a, NULL), bl = GetFullPathNameW(right, _countof(b), b, NULL);
  if (!al || al >= _countof(a) || !bl || bl >= _countof(b)) return FALSE;
  for (DWORD i = 0; a[i]; i++) if (a[i] == L'/') a[i] = L'\\';
  for (DWORD i = 0; b[i]; i++) if (b[i] == L'/') b[i] = L'\\';
  while (wcslen(a) > 3 && a[wcslen(a)-1] == L'\\') a[wcslen(a)-1] = 0;
  while (wcslen(b) > 3 && b[wcslen(b)-1] == L'\\') b[wcslen(b)-1] = 0;
  return _wcsicmp(a, b) == 0;
}

static BOOL equal_windows_fragment(const wchar_t *left, const wchar_t *right) {
  wchar_t a[MAX_PATH], b[MAX_PATH];
  wcsncpy_s(a, _countof(a), left, _TRUNCATE); wcsncpy_s(b, _countof(b), right, _TRUNCATE);
  for (DWORD i = 0; a[i]; i++) if (a[i] == L'/') a[i] = L'\\';
  for (DWORD i = 0; b[i]; i++) if (b[i] == L'/') b[i] = L'\\';
  while (wcslen(a) > 1 && a[wcslen(a)-1] == L'\\') a[wcslen(a)-1] = 0;
  while (wcslen(b) > 1 && b[wcslen(b)-1] == L'\\') b[wcslen(b)-1] = 0;
  return _wcsicmp(a, b) == 0;
}

static int probe_environment(int argc, wchar_t **argv) {
  wchar_t home[MAX_PATH], profile[MAX_PATH], temp[MAX_PATH], tmp[MAX_PATH], drive[MAX_PATH], pathpart[MAX_PATH], appcontainer_temp[MAX_PATH];
  DWORD secret = GetEnvironmentVariableW(L"CAPLOCK_TEST_SECRET", NULL, 0);
  if (secret != 0) { fwprintf(stderr, L"caplock-sandbox: probe environment secret is visible\n"); return 30; }
  if (argc != 6 || GetEnvironmentVariableW(L"HOME", home, _countof(home)) == 0 || GetEnvironmentVariableW(L"USERPROFILE", profile, _countof(profile)) == 0 || GetEnvironmentVariableW(L"TEMP", temp, _countof(temp)) == 0 || GetEnvironmentVariableW(L"TMP", tmp, _countof(tmp)) == 0 || GetEnvironmentVariableW(L"HOMEDRIVE", drive, _countof(drive)) == 0 || GetEnvironmentVariableW(L"HOMEPATH", pathpart, _countof(pathpart)) == 0) { fwprintf(stderr, L"caplock-sandbox: probe synthetic environment variable missing or expected values absent\n"); return 31; }
  DWORD app_temp_len = GetTempPathW(_countof(appcontainer_temp), appcontainer_temp);
  if (!app_temp_len || app_temp_len >= _countof(appcontainer_temp)) { fwprintf(stderr, L"caplock-sandbox: probe GetTempPathW failed (%lu)\n", GetLastError()); return 33; }
  wprintf(L"HOME=%ls\nUSERPROFILE=%ls\nTEMP=%ls\nTMP=%ls\nHOMEDRIVE=%ls\nHOMEPATH=%ls\nAPP_CONTAINER_TEMP=%ls\n", home, profile, temp, tmp, drive, pathpart, appcontainer_temp);
  if (!equal_windows_path(home, argv[2]) || !equal_windows_path(profile, argv[3]) || !equal_windows_path(temp, appcontainer_temp) || !equal_windows_path(tmp, appcontainer_temp) || !equal_windows_fragment(drive, argv[4]) || !equal_windows_fragment(pathpart, argv[5])) {
    fwprintf(stderr, L"caplock-sandbox: probe synthetic environment mismatch; expected HOME=%ls USERPROFILE=%ls HOMEDRIVE=%ls HOMEPATH=%ls; AppContainer TEMP/TMP expected GetTempPathW=%ls\n", argv[2], argv[3], argv[4], argv[5], appcontainer_temp); return 32;
  }
  return 0;
}

static int selftest(void) {
  wchar_t root[MAX_PATH], package[MAX_PATH], temp[MAX_PATH], marker[MAX_PATH], probe[MAX_PATH], module[MAX_PATH];
  wchar_t *args[12]; DWORD length;
  length = GetTempPathW(_countof(root), root); if (length == 0 || length >= _countof(root)) return 1;
  if (!GetTempFileNameW(root, L"clk", 0, root)) return 1;
  DeleteFileW(root); if (!CreateDirectoryW(root, NULL)) return 1;
  swprintf_s(package, _countof(package), L"%ls\\package", root); swprintf_s(temp, _countof(temp), L"%ls\\temp", root); swprintf_s(marker, _countof(marker), L"%ls\\marker", package); swprintf_s(probe, _countof(probe), L"%ls\\caplock-probe.exe", package);
  if (!CreateDirectoryW(package, NULL) || !CreateDirectoryW(temp, NULL) || !GetModuleFileNameW(NULL, module, _countof(module)) || !CopyFileW(module, probe, FALSE)) { print_last_error(L"selftest fixture setup"); RemoveDirectoryW(root); return 1; }
  args[0] = L"caplock-sandbox"; args[1] = L"--package"; args[2] = package; args[3] = L"--temp"; args[4] = temp; args[5] = L"--cwd"; args[6] = package; args[7] = L"--network"; args[8] = L"none"; args[9] = L"--"; args[10] = probe; args[11] = L"--probe-write";
  { wchar_t *full_args[13]; int code; BOOL allowed, cleanup;
    CopyMemory(full_args, args, sizeof(args)); full_args[12] = marker;
    ZeroMemory(&selftest_status, sizeof(selftest_status)); selftest_running = TRUE;
    code = wmain(13, full_args); selftest_running = FALSE;
    allowed = GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES;
    if (!allowed) print_last_error(L"selftest marker creation");
    DeleteFileW(marker); DeleteFileW(probe); RemoveDirectoryW(temp); RemoveDirectoryW(package); cleanup = RemoveDirectoryW(root);
    if (!cleanup) print_last_error(L"selftest cleanup");
    if (code != 0) fwprintf(stderr, L"caplock-sandbox: selftest child exit code %d (profile=%d launch=%d token=%d marker=%d cleanup=%d)\n", code, selftest_status.profileCreated, selftest_status.processLaunched, selftest_status.tokenIsAppContainer, allowed, cleanup);
    wprintf(L"{\"profileCreated\":%s,\"processLaunched\":%s,\"tokenIsAppContainer\":%s,\"allowedWrite\":%s,\"cleanup\":%s,\"stage\":\"%ls\"}\n",
      selftest_status.profileCreated ? L"true" : L"false", selftest_status.processLaunched ? L"true" : L"false",
      selftest_status.tokenIsAppContainer ? L"true" : L"false", allowed ? L"true" : L"false", cleanup ? L"true" : L"false", (code == 0 && allowed && cleanup) ? L"complete" : L"failed");
    return (code == 0 && selftest_status.profileCreated && selftest_status.processLaunched && selftest_status.tokenIsAppContainer && allowed && cleanup) ? 0 : 1; }
}

/* This mode runs only after the ordinary launcher has placed this probe in an
   AppContainer Job. It distinguishes ordinary native descendant creation from
   Node/libuv's spawnSync behavior without granting any new access. */
/* libuv's default spawnSync stdio uses anonymous-looking named pipe pairs.
   Exercise that Windows primitive directly so this probe can distinguish a
   pipe/AppContainer restriction from libuv's process bookkeeping. */
static BOOL create_probe_named_pipe_pair(const wchar_t *name, DWORD server_access, DWORD client_access, HANDLE *server, HANDLE *client, DWORD *error_code) {
  SECURITY_ATTRIBUTES inherit; BOOL connected;
  ZeroMemory(&inherit, sizeof(inherit)); inherit.nLength = sizeof(inherit); inherit.bInheritHandle = TRUE;
  *server = CreateNamedPipeW(name, server_access, PIPE_TYPE_BYTE | PIPE_WAIT,
    1, 4096, 4096, 0, NULL);
  if (*server == INVALID_HANDLE_VALUE) { *error_code = GetLastError(); return FALSE; }
  *client = CreateFileW(name, client_access, 0, &inherit, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (*client == INVALID_HANDLE_VALUE) { *error_code = GetLastError(); CloseHandle(*server); *server = INVALID_HANDLE_VALUE; return FALSE; }
  connected = ConnectNamedPipe(*server, NULL);
  if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) { *error_code = GetLastError(); CloseHandle(*client); CloseHandle(*server); *client = *server = INVALID_HANDLE_VALUE; return FALSE; }
  return TRUE;
}

static int probe_native_child(const wchar_t *result_name, const wchar_t *node_path) {
  wchar_t module[MAX_PATH] = L"", command_line[2 * MAX_PATH] = L"";
  wchar_t pipe_name[3][MAX_PATH] = { L"", L"", L"" };
  PROCESS_INFORMATION child; STARTUPINFOW startup; HANDLE servers[3] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE }, clients[3] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
  DWORD wait = WAIT_FAILED, exit_code = 1, error_code = 0, pipe_wait = WAIT_FAILED, pipe_exit_code = 1, pipe_error = 0; BOOL created = FALSE, appcontainer = FALSE, in_job = FALSE, pipe_attempted = FALSE, pipe_created = FALSE, pipe_child_created = FALSE;
  GetModuleFileNameW(NULL, module, _countof(module));
  if (!append_argument(command_line, _countof(command_line), node_path) || !append_argument(command_line, _countof(command_line), L"-e") || !append_argument(command_line, _countof(command_line), L"process.exit(0)")) error_code = ERROR_BUFFER_OVERFLOW;
  else {
    ZeroMemory(&startup, sizeof(startup)); startup.cb = sizeof(startup); ZeroMemory(&child, sizeof(child));
    if (CreateProcessW(node_path, command_line, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &startup, &child)) {
      created = TRUE; appcontainer = child_is_appcontainer(child.hProcess); IsProcessInJob(child.hProcess, NULL, &in_job);
      if (ResumeThread(child.hThread) != (DWORD)-1) { wait = WaitForSingleObject(child.hProcess, 1000); if (wait == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &exit_code); }
      else error_code = GetLastError();
      CloseHandle(child.hThread); CloseHandle(child.hProcess);
    } else error_code = GetLastError();
  }
  /* The first pair supplies stdin (server writes, child reads); the other
     two collect stdout/stderr (child writes, server reads). */
  pipe_attempted = TRUE;
  for (int i = 0; i < 3; i++) swprintf_s(pipe_name[i], _countof(pipe_name[i]), L"\\\\.\\pipe\\LOCAL\\caplock-selftest-%lu-%lu-%d", GetCurrentProcessId(), GetTickCount(), i);
  if (create_probe_named_pipe_pair(pipe_name[0], PIPE_ACCESS_OUTBOUND, GENERIC_READ, &servers[0], &clients[0], &pipe_error) &&
      create_probe_named_pipe_pair(pipe_name[1], PIPE_ACCESS_INBOUND, GENERIC_WRITE, &servers[1], &clients[1], &pipe_error) &&
      create_probe_named_pipe_pair(pipe_name[2], PIPE_ACCESS_INBOUND, GENERIC_WRITE, &servers[2], &clients[2], &pipe_error)) {
    pipe_created = TRUE; ZeroMemory(&startup, sizeof(startup)); startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = clients[0]; startup.hStdOutput = clients[1]; startup.hStdError = clients[2]; ZeroMemory(&child, sizeof(child));
    if (CreateProcessW(node_path, command_line, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &startup, &child)) {
      pipe_child_created = TRUE;
      if (ResumeThread(child.hThread) != (DWORD)-1) { pipe_wait = WaitForSingleObject(child.hProcess, 1000); if (pipe_wait == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &pipe_exit_code); }
      CloseHandle(child.hThread); CloseHandle(child.hProcess);
    }
  }
  for (int i = 0; i < 3; i++) { if (clients[i] != INVALID_HANDLE_VALUE) CloseHandle(clients[i]); if (servers[i] != INVALID_HANDLE_VALUE) CloseHandle(servers[i]); }
  { HANDLE file = CreateFileW(result_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); char json[512]; DWORD written;
    int count = _snprintf_s(json, sizeof(json), _TRUNCATE, "{\"nativeChildCreateAttempted\":true,\"nativeChildCreated\":%s,\"nativeChildIsAppContainer\":%s,\"nativeChildInJob\":%s,\"nativeChildExited\":%s,\"nativeChildExitCode\":%s,\"nativeChildError\":%s,\"nativeNamedPipeAttempted\":%s,\"nativeNamedPipeCreated\":%s,\"nativeNamedPipeError\":%s,\"nativePipeChildCreated\":%s,\"nativePipeChildExited\":%s,\"nativePipeChildExitCode\":%s}", created ? "true" : "false", appcontainer ? "true" : "false", in_job ? "true" : "false", wait == WAIT_OBJECT_0 ? "true" : "false", wait == WAIT_OBJECT_0 ? (exit_code == 0 ? "0" : "1") : "null", error_code ? "\"native-create-failed\"" : "null", pipe_attempted ? "true" : "false", pipe_created ? "true" : "false", pipe_error ? "\"native-pipe-failed\"" : "null", pipe_child_created ? "true" : "false", pipe_wait == WAIT_OBJECT_0 ? "true" : "false", pipe_wait == WAIT_OBJECT_0 ? (pipe_exit_code == 0 ? "0" : "1") : "null");
    if (file != INVALID_HANDLE_VALUE && count > 0) { WriteFile(file, json, (DWORD)count, &written, NULL); CloseHandle(file); }
  }
  return created && appcontainer && in_job && wait == WAIT_OBJECT_0 && exit_code == 0 ? 0 : 1;
}

/* The selftest enters the ordinary launcher through the same UTF-16 custom
   environment-file path as production.  It deliberately contains only the
   production Windows bootstrap variables and no ambient Node configuration. */
static BOOL write_selftest_environment(const wchar_t *path, const wchar_t *home, const wchar_t *node_options) {
  wchar_t block[32768] = L"", value[MAX_PATH] = L"", system_root[MAX_PATH] = L"C:\\Windows", home_drive[3] = { home[0], L':', L'\0' };
  size_t used = 0; HANDLE file; DWORD written;
  const wchar_t *names[] = { L"ALLUSERSPROFILE", L"APPDATA", L"ComSpec", L"HOME", L"HOMEDRIVE", L"HOMEPATH", L"LOCALAPPDATA", L"NODE_OPTIONS", L"OS", L"PATH", L"PATHEXT", L"PROCESSOR_ARCHITECTURE", L"ProgramData", L"SystemDrive", L"SystemRoot", L"TEMP", L"TMP", L"USERPROFILE", L"WINDIR" };
  for (size_t i = 0; i < _countof(names); i++) {
    const wchar_t *contents;
    if (wcscmp(names[i], L"NODE_OPTIONS") == 0) contents = node_options;
    else if (wcscmp(names[i], L"HOME") == 0 || wcscmp(names[i], L"TEMP") == 0 || wcscmp(names[i], L"TMP") == 0 || wcscmp(names[i], L"USERPROFILE") == 0) contents = home;
    else if (wcscmp(names[i], L"HOMEDRIVE") == 0) contents = home_drive;
    else if (wcscmp(names[i], L"HOMEPATH") == 0) contents = home + 2;
    else { if (wcscmp(names[i], L"SystemRoot") == 0 || wcscmp(names[i], L"WINDIR") == 0) GetEnvironmentVariableW(L"SystemRoot", system_root, _countof(system_root)); value[0] = L'\0'; GetEnvironmentVariableW(names[i], value, _countof(value)); contents = value[0] ? value : ((wcscmp(names[i], L"SystemRoot") == 0 || wcscmp(names[i], L"WINDIR") == 0) ? system_root : L""); }
    if (FAILED(StringCchPrintfW(block + used, _countof(block) - used, L"%ls=%ls", names[i], contents))) return FALSE;
    used += wcslen(block + used) + 1;
  }
  if (used + 1 >= _countof(block)) return FALSE; block[used++] = L'\0';
  file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE || !WriteFile(file, block, (DWORD)(used * sizeof(wchar_t)), &written, NULL) || written != used * sizeof(wchar_t)) { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); return FALSE; }
  CloseHandle(file); return TRUE;
}

/* Reproduce a package-local `node script.js` lifecycle that synchronously
   spawns process.execPath. The normal launcher below supplies the real
   AppContainer token, ACL grants, suspended launch, and Job Object. */
static int selftest_spawn(void) {
  wchar_t root[MAX_PATH] = L"", modules[MAX_PATH] = L"", package[MAX_PATH] = L"", runtime[MAX_PATH] = L"", temp[MAX_PATH] = L"", home[MAX_PATH] = L"", node_source[MAX_PATH] = L"", node_stage[MAX_PATH] = L"", shim_source[MAX_PATH] = L"", shim_stage[MAX_PATH] = L"", node_options[2 * MAX_PATH] = L"";
  wchar_t parent_script[MAX_PATH] = L"", env_file[MAX_PATH] = L"", result_path[MAX_PATH] = L"", ignore_result_path[MAX_PATH] = L"", inherit_result_path[MAX_PATH] = L"", native_result_path[MAX_PATH] = L"", native_probe[MAX_PATH] = L"", module[MAX_PATH] = L"", started_marker[MAX_PATH] = L"", reached_marker[MAX_PATH] = L"", node_spawn_marker[MAX_PATH] = L"", node_exec_path[MAX_PATH] = L"";
  wchar_t *args[23]; HANDLE file = INVALID_HANDLE_VALUE; DWORD length, node_length, written, read = 0; int code, native_code; BOOL cleanup, parent_started, parent_reached, node_spawn_started;
  char json[1024] = "", ignore_json[512] = "", inherit_json[512] = "", native_json[1024] = "";
  static const char script[] =
    "const fs=require('fs'),cp=require('child_process');\n"
    "fs.writeFileSync('parent-started.marker','ok');\n"
    "let out={defaultPipeSpawnStarted:false,defaultPipeChildObserved:false,defaultPipeSpawnReturned:false,defaultPipeStatus:null,defaultPipeErrorCode:null,defaultPipeSignal:null,defaultPipeStdoutClosed:false,defaultPipeStderrClosed:false,defaultPipeGrandchildReturned:false,nodeSpawnReturned:false,nodeSpawnError:false,nodeSpawnTimedOut:false,nodeChildExitCode:null,parentContinued:false,errorCode:null};\n"
    "out.parentReachedSpawn=true;fs.writeFileSync('parent-reached-spawn.marker','ok');\n"
    "fs.writeFileSync('node-exec-path.txt',process.execPath);const control=cp.spawnSync(process.execPath,['-e','process.exit(0)'],{timeout:1000,stdio:'ignore'});fs.writeFileSync('node-stdio-ignore.json',JSON.stringify({returned:true,status:control.status,error:control.error&&control.error.code||null}));const inherited=cp.spawnSync(process.execPath,['-e','process.exit(0)'],{timeout:1000,stdio:'inherit'});fs.writeFileSync('node-stdio-inherit.json',JSON.stringify({returned:true,status:inherited.status,error:inherited.error&&inherited.error.code||null}));\n"
    "fs.writeFileSync('node-spawn-started.marker','ok');out.defaultPipeSpawnStarted=true;try{const childCode=\"const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');try{fs.writeFileSync(path.resolve(process.cwd(),'..','..','selftest-escape.txt'),'escape');process.exit(18)}catch(e){}const r=cp.spawnSync(process.execPath,['-e',\\\"process.stdout.write('grandchild')\\\"],{timeout:3000});if(r.status===0&&Buffer.isBuffer(r.stdout)&&r.stdout.toString()==='grandchild'&&!r.error){process.stdout.write('hello');process.exit(0)}else{process.exit(17)}\";const r=cp.spawnSync(process.execPath,['-e',childCode],{timeout:3000});out.defaultPipeSpawnReturned=true;out.defaultPipeStatus=r.status;out.defaultPipeErrorCode=r.error&&r.error.code||null;out.defaultPipeSignal=r.signal||null;out.defaultPipeStdoutClosed=Buffer.isBuffer(r.stdout)&&r.stdout.toString()==='hello';out.defaultPipeStderrClosed=Buffer.isBuffer(r.stderr)&&r.stderr.length===0;out.defaultPipeGrandchildReturned=r.status===0&&Buffer.isBuffer(r.stdout)&&r.stdout.toString()==='hello';out.nodeSpawnReturned=true;out.nodeChildExitCode=r.status;out.nodeSpawnError=Boolean(r.error);out.nodeSpawnTimedOut=Boolean(r.error&&r.error.code==='ETIMEDOUT');out.errorCode=out.defaultPipeErrorCode;}catch(e){out.nodeSpawnError=true;out.errorCode=e&&e.code||'exception';out.defaultPipeErrorCode=out.errorCode;}\n"
    "out.parentContinued=true;fs.writeFileSync('spawn-result.json',JSON.stringify(out));process.exit(out.nodeSpawnReturned&&out.nodeChildExitCode===0?0:2);\n";
  length = GetTempPathW(_countof(root), root); if (!length || length >= _countof(root) || !GetTempFileNameW(root, L"clk", 0, root)) goto setup_fail;
  DeleteFileW(root); if (!CreateDirectoryW(root, NULL)) goto setup_fail;
  swprintf_s(modules, _countof(modules), L"%ls\\node_modules", root); swprintf_s(package, _countof(package), L"%ls\\fixture-dependency", modules); swprintf_s(runtime, _countof(runtime), L"%ls\\runtime", root); swprintf_s(temp, _countof(temp), L"%ls\\temp", root); swprintf_s(home, _countof(home), L"%ls\\home", temp);
  swprintf_s(node_stage, _countof(node_stage), L"%ls\\0-node.exe", runtime); swprintf_s(shim_stage, _countof(shim_stage), L"%ls\\caplock-pipe-shim.node", runtime); swprintf_s(parent_script, _countof(parent_script), L"%ls\\spawn-parent.js", package); swprintf_s(env_file, _countof(env_file), L"%ls\\child-environment.utf16", temp); swprintf_s(result_path, _countof(result_path), L"%ls\\spawn-result.json", package); swprintf_s(ignore_result_path, _countof(ignore_result_path), L"%ls\\node-stdio-ignore.json", package); swprintf_s(inherit_result_path, _countof(inherit_result_path), L"%ls\\node-stdio-inherit.json", package); swprintf_s(native_result_path, _countof(native_result_path), L"%ls\\native-result.json", package); swprintf_s(native_probe, _countof(native_probe), L"%ls\\native-probe.exe", package);
  swprintf_s(started_marker, _countof(started_marker), L"%ls\\parent-started.marker", package); swprintf_s(reached_marker, _countof(reached_marker), L"%ls\\parent-reached-spawn.marker", package); swprintf_s(node_spawn_marker, _countof(node_spawn_marker), L"%ls\\node-spawn-started.marker", package); swprintf_s(node_exec_path, _countof(node_exec_path), L"%ls\\node-exec-path.txt", package);
  if (!CreateDirectoryW(modules, NULL) || !CreateDirectoryW(package, NULL) || !CreateDirectoryW(runtime, NULL) || !CreateDirectoryW(temp, NULL) || !CreateDirectoryW(home, NULL)) goto setup_fail;
  node_length = SearchPathW(NULL, L"node.exe", NULL, _countof(node_source), node_source, NULL);
  if (!node_length || node_length >= _countof(node_source) || !CopyFileW(node_source, node_stage, FALSE) || !GetModuleFileNameW(NULL, module, _countof(module))) goto setup_fail;
  { wchar_t *separator = wcsrchr(module, L'\\'); wchar_t saved; if (separator == NULL) goto setup_fail; saved = *(separator + 1); *(separator + 1) = L'\0'; if (FAILED(StringCchPrintfW(shim_source, _countof(shim_source), L"%lscaplock-pipe-shim.node", module))) goto setup_fail; *(separator + 1) = saved; if (!CopyFileW(shim_source, shim_stage, FALSE) || !CopyFileW(module, native_probe, FALSE)) goto setup_fail; }
  file = CreateFileW(parent_script, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE || !WriteFile(file, script, (DWORD)(sizeof(script) - 1), &written, NULL) || written != sizeof(script) - 1) goto setup_fail;
  CloseHandle(file); file = INVALID_HANDLE_VALUE;
  if (FAILED(StringCchPrintfW(node_options, _countof(node_options), L"--preserve-symlinks --require=%ls", shim_stage)) || !write_selftest_environment(env_file, home, node_options)) goto setup_fail;
  args[0]=L"caplock-sandbox"; args[1]=L"--package"; args[2]=package; args[3]=L"--temp"; args[4]=temp; args[5]=L"--cwd"; args[6]=package; args[7]=L"--network"; args[8]=L"none"; args[9]=L"--env-file"; args[10]=env_file; args[11]=L"--read"; args[12]=runtime; args[13]=L"--read"; args[14]=node_stage; args[15]=L"--watchdog-ms"; args[16]=L"5000"; args[17]=L"--"; args[18]=native_probe; args[19]=L"--probe-native-child"; args[20]=L"native-result.json"; args[21]=node_stage;
  ZeroMemory(&selftest_status, sizeof(selftest_status)); selftest_running = TRUE; native_code = wmain(22, args); selftest_running = FALSE;
  file = CreateFileW(native_result_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { read = 0; ReadFile(file, native_json, sizeof(native_json) - 1, &read, NULL); CloseHandle(file); native_json[read] = '\0'; }
  args[18]=node_stage; args[19]=L"--preserve-symlinks-main"; args[20]=L"spawn-parent.js";
  ZeroMemory(&selftest_status, sizeof(selftest_status)); selftest_running = TRUE; code = wmain(21, args); selftest_running = FALSE;
  file = CreateFileW(ignore_result_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { read = 0; ReadFile(file, ignore_json, sizeof(ignore_json) - 1, &read, NULL); CloseHandle(file); ignore_json[read] = '\0'; }
  file = CreateFileW(inherit_result_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { read = 0; ReadFile(file, inherit_json, sizeof(inherit_json) - 1, &read, NULL); CloseHandle(file); inherit_json[read] = '\0'; }
  file = CreateFileW(result_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) { ReadFile(file, json, sizeof(json) - 1, &read, NULL); CloseHandle(file); json[read] = '\0'; }
  parent_started = GetFileAttributesW(started_marker) != INVALID_FILE_ATTRIBUTES; parent_reached = GetFileAttributesW(reached_marker) != INVALID_FILE_ATTRIBUTES; node_spawn_started = GetFileAttributesW(node_spawn_marker) != INVALID_FILE_ATTRIBUTES;
  DeleteFileW(result_path); DeleteFileW(ignore_result_path); DeleteFileW(inherit_result_path); DeleteFileW(native_result_path); DeleteFileW(started_marker); DeleteFileW(reached_marker); DeleteFileW(node_spawn_marker); DeleteFileW(node_exec_path); DeleteFileW(parent_script); DeleteFileW(env_file); DeleteFileW(node_stage); DeleteFileW(shim_stage); DeleteFileW(native_probe); RemoveDirectoryW(home); RemoveDirectoryW(temp); RemoveDirectoryW(package); RemoveDirectoryW(modules); RemoveDirectoryW(runtime); cleanup = RemoveDirectoryW(root);
  wprintf(L"{\"nativeChildCreateAttempted\":%s,\"nativeChildCreated\":%s,\"nativeChildIsAppContainer\":%s,\"nativeChildInJob\":%s,\"nativeChildExited\":%s,\"nativeChildExitCode\":%s,\"nativeNamedPipeAttempted\":%s,\"nativeNamedPipeCreated\":%s,\"nativePipeChildCreated\":%s,\"nativePipeChildExited\":%s,\"nativePipeChildExitCode\":%s,\"nodeIgnoreStdioReturned\":%s,\"nodeIgnoreStdioExitCode\":%s,\"nodeIgnoreStdioError\":%s,\"nodeInheritStdioReturned\":%s,\"nodeInheritStdioExitCode\":%s,\"defaultPipeSpawnStarted\":%s,\"defaultPipeChildObserved\":%s,\"defaultPipeSpawnReturned\":%s,\"defaultPipeStatus\":%s,\"defaultPipeErrorCode\":%s,\"defaultPipeSignal\":%s,\"defaultPipeStdoutClosed\":%s,\"defaultPipeStderrClosed\":%s,\"defaultPipeGrandchildReturned\":%s,\"parentCreated\":%s,\"parentIsAppContainer\":%s,\"parentScriptStarted\":%s,\"parentReachedSpawn\":%s,\"nodeSpawnStarted\":%s,\"nodeChildObserved\":%s,\"nodeSpawnReturned\":%s,\"nodeSpawnError\":%s,\"nodeSpawnTimedOut\":%s,\"nodeChildExitCode\":%s,\"childSpawnReturned\":%s,\"childExitCode\":%s,\"parentExited\":%s,\"jobClean\":%s,\"cleanup\":%s,\"stage\":\"%ls\",\"errorCode\":%s}\n",
    native_json[0] ? L"true" : L"false", strstr(native_json, "\"nativeChildCreated\":true") ? L"true" : L"false", strstr(native_json, "\"nativeChildIsAppContainer\":true") ? L"true" : L"false", strstr(native_json, "\"nativeChildInJob\":true") ? L"true" : L"false", strstr(native_json, "\"nativeChildExited\":true") ? L"true" : L"false", strstr(native_json, "\"nativeChildExitCode\":0") ? L"0" : L"null", strstr(native_json, "\"nativeNamedPipeAttempted\":true") ? L"true" : L"false", strstr(native_json, "\"nativeNamedPipeCreated\":true") ? L"true" : L"false", strstr(native_json, "\"nativePipeChildCreated\":true") ? L"true" : L"false", strstr(native_json, "\"nativePipeChildExited\":true") ? L"true" : L"false", strstr(native_json, "\"nativePipeChildExitCode\":0") ? L"0" : L"null", strstr(ignore_json, "\"returned\":true") ? L"true" : L"false", strstr(ignore_json, "\"status\":0") ? L"0" : L"null", strstr(ignore_json, "\"error\":\"ETIMEDOUT\"") ? L"\"ETIMEDOUT\"" : (strstr(ignore_json, "\"error\":null") ? L"null" : L"\"unknown\""), strstr(inherit_json, "\"returned\":true") ? L"true" : L"false", strstr(inherit_json, "\"status\":0") ? L"0" : L"null", node_spawn_started ? L"true" : L"false", selftest_status.nodeChildObserved ? L"true" : L"false", strstr(json, "\"defaultPipeSpawnReturned\":true") ? L"true" : L"false", strstr(json, "\"defaultPipeStatus\":0") ? L"0" : L"null", strstr(json, "\"defaultPipeErrorCode\":null") ? L"null" : L"\"unavailable\"", strstr(json, "\"defaultPipeSignal\":null") ? L"null" : L"\"signal\"", strstr(json, "\"defaultPipeStdoutClosed\":true") ? L"true" : L"false", strstr(json, "\"defaultPipeStderrClosed\":true") ? L"true" : L"false", strstr(json, "\"defaultPipeGrandchildReturned\":true") ? L"true" : L"false", selftest_status.processLaunched ? L"true" : L"false", selftest_status.tokenIsAppContainer ? L"true" : L"false", parent_started ? L"true" : L"false", parent_reached ? L"true" : L"false", node_spawn_started ? L"true" : L"false", selftest_status.nodeChildObserved ? L"true" : L"false", strstr(json, "\"nodeSpawnReturned\":true") ? L"true" : L"false", strstr(json, "\"nodeSpawnError\":true") ? L"true" : L"false", strstr(json, "\"nodeSpawnTimedOut\":true") ? L"true" : L"false", strstr(json, "\"nodeChildExitCode\":0") ? L"0" : L"null", strstr(json, "\"nodeSpawnReturned\":true") ? L"true" : L"false", strstr(json, "\"nodeChildExitCode\":0") ? L"0" : L"null", selftest_status.parentExited ? L"true" : L"false", selftest_status.jobClean ? L"true" : L"false", cleanup ? L"true" : L"false", code == 0 && native_code == 0 && !selftest_status.watchdogFired && parent_started && parent_reached ? L"complete" : (selftest_status.watchdogFired ? L"watchdog" : (parent_started ? (parent_reached ? L"nested-spawn" : L"parent-before-spawn") : L"parent-script")), selftest_status.watchdogFired ? L"\"outer-watchdog\"" : (native_code != 0 ? L"\"native-child-failed\"" : (strstr(json, "\"errorCode\":null") ? L"null" : L"\"node-spawn-failed\"")));
  return code == 0 && native_code == 0 && selftest_status.processLaunched && selftest_status.tokenIsAppContainer && parent_started && parent_reached && !selftest_status.watchdogFired && strstr(json, "\"defaultPipeSpawnReturned\":true") && strstr(json, "\"defaultPipeStatus\":0") && strstr(json, "\"defaultPipeStdoutClosed\":true") && strstr(json, "\"defaultPipeStderrClosed\":true") && strstr(json, "\"defaultPipeGrandchildReturned\":true") && cleanup ? 0 : 1;
setup_fail:
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  DeleteFileW(result_path); DeleteFileW(ignore_result_path); DeleteFileW(inherit_result_path); DeleteFileW(native_result_path); DeleteFileW(started_marker); DeleteFileW(reached_marker); DeleteFileW(node_spawn_marker); DeleteFileW(node_exec_path); DeleteFileW(parent_script); DeleteFileW(env_file); DeleteFileW(node_stage); DeleteFileW(shim_stage); DeleteFileW(native_probe); RemoveDirectoryW(home); RemoveDirectoryW(temp); RemoveDirectoryW(package); RemoveDirectoryW(modules); RemoveDirectoryW(runtime); RemoveDirectoryW(root);
  wprintf(L"{\"parentCreated\":false,\"parentIsAppContainer\":false,\"parentScriptStarted\":false,\"parentReachedSpawn\":false,\"childSpawnReturned\":false,\"childExitCode\":null,\"parentExited\":false,\"jobClean\":false,\"cleanup\":false,\"stage\":\"setup\",\"errorCode\":\"setup-failed\"}\n");
  return 1;
}

int wmain(int argc, wchar_t **argv) {
  const wchar_t *package_path = NULL, *temp_path = NULL, *cwd = NULL, *network = NULL, *env_file = NULL, *watchdog_text = NULL;
  const wchar_t *reads[MAX_GRANTS] = { NULL }, *writes[MAX_GRANTS] = { NULL };
  int read_count = 0, write_count = 0, command_index = -1, index;
  wchar_t profile_name[128], *command_line = NULL;
  PSID appcontainer_sid = NULL, network_sid = NULL, private_network_sid = NULL;
  SID_AND_ATTRIBUTES capabilities[2];
  SECURITY_CAPABILITIES security_capabilities;
  SIZE_T attributes_size = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  HANDLE inherited_stdio[3] = { NULL, NULL, NULL };
  STARTUPINFOEXW startup;
  PROCESS_INFORMATION child = { 0 };
  LPWCH child_environment = NULL;
  BOOL child_environment_inherited = FALSE;
  HANDLE job = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  SavedAcl acls[MAX_GRANTS + 2] = { 0 }; int acl_count = 0;
  BOOL profile_created = FALSE, success = FALSE;
  BOOL null_stdio = FALSE;
  DWORD exit_code = 1, watchdog_ms = INFINITE;

  if (argc == 2 && wcscmp(argv[1], L"--help") == 0) { wprintf(L"Usage: caplock-sandbox --package DIR --temp DIR --cwd DIR --network none|host --env-file FILE [--read DIR] [--write DIR] -- EXECUTABLE [ARGS...]\n       caplock-sandbox --selftest | --selftest-spawn\n"); return 0; }
  if (argc == 2 && wcscmp(argv[1], L"--selftest") == 0) return selftest();
  if (argc == 2 && wcscmp(argv[1], L"--selftest-spawn") == 0) return selftest_spawn();
  if (argc == 2 && wcscmp(argv[1], L"--probe-exit") == 0) return 0;
  if (argc == 4 && wcscmp(argv[1], L"--probe-native-child") == 0) return probe_native_child(argv[2], argv[3]);
  if (argc == 3 && wcscmp(argv[1], L"--probe-write") == 0) return probe_write(argv[2]);
  if (argc >= 2 && wcscmp(argv[1], L"--probe-env") == 0) return probe_environment(argc, argv);

  for (index = 1; index < argc; index++) {
    if (wcscmp(argv[index], L"--") == 0) { command_index = index + 1; break; }
    if (index + 1 >= argc) { fwprintf(stderr, L"caplock-sandbox: missing value\n"); goto cleanup; }
    if (wcscmp(argv[index], L"--package") == 0) package_path = argv[++index];
    else if (wcscmp(argv[index], L"--temp") == 0) temp_path = argv[++index];
    else if (wcscmp(argv[index], L"--cwd") == 0) cwd = argv[++index];
    else if (wcscmp(argv[index], L"--network") == 0) network = argv[++index];
    else if (wcscmp(argv[index], L"--env-file") == 0) env_file = argv[++index];
    else if (wcscmp(argv[index], L"--watchdog-ms") == 0) watchdog_text = argv[++index];
    else if (wcscmp(argv[index], L"--null-stdio") == 0) null_stdio = TRUE;
    else if (wcscmp(argv[index], L"--read") == 0 && read_count < MAX_GRANTS) reads[read_count++] = argv[++index];
    else if (wcscmp(argv[index], L"--write") == 0 && write_count < MAX_GRANTS) writes[write_count++] = argv[++index];
    else { fwprintf(stderr, L"caplock-sandbox: invalid argument\n"); goto cleanup; }
  }
  if (package_path == NULL || temp_path == NULL || cwd == NULL || network == NULL || (!selftest_running && env_file == NULL) || command_index < 0 || command_index >= argc) {
    fwprintf(stderr, L"caplock-sandbox: --package, --temp, --cwd, --network, --env-file and command are required\n"); goto cleanup;
  }
  if (wcscmp(network, L"none") != 0 && wcscmp(network, L"host") != 0) { fwprintf(stderr, L"caplock-sandbox: invalid network mode\n"); goto cleanup; }
  if (watchdog_text != NULL) { wchar_t *end = NULL; unsigned long parsed = wcstoul(watchdog_text, &end, 10); if (end == watchdog_text || *end != L'\0' || parsed == 0) { fwprintf(stderr, L"caplock-sandbox: invalid watchdog\n"); goto cleanup; } watchdog_ms = parsed; }
  debug_control_context(network);
  if (!CreateDirectoryW(temp_path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { print_last_error(L"CreateDirectoryW"); goto cleanup; }

  swprintf_s(profile_name, _countof(profile_name), L"CapLock-%lu-%lu-%lu", GetCurrentProcessId(), GetTickCount(), (unsigned long)(GetTickCount64() & 0xffffffffULL));
  { HRESULT profile_result = CreateAppContainerProfile(profile_name, profile_name, L"CapLock temporary sandbox", NULL, 0, &appcontainer_sid);
    if (FAILED(profile_result)) { fwprintf(stderr, L"caplock-sandbox: cannot create unique AppContainer profile (HRESULT 0x%08lX)\n", (unsigned long)profile_result); goto cleanup; }
  }
  profile_created = TRUE;
  if (selftest_running) selftest_status.profileCreated = TRUE;
  if (!grant_appcontainer_access(package_path, appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;
  if (!grant_appcontainer_access(temp_path, appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;
  for (index = 0; index < read_count; index++) if (!grant_appcontainer_access(reads[index], appcontainer_sid, GENERIC_READ | GENERIC_EXECUTE, &acls[acl_count++])) goto cleanup;
  for (index = 0; index < write_count; index++) if (!grant_appcontainer_access(writes[index], appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;

  ZeroMemory(&security_capabilities, sizeof(security_capabilities)); security_capabilities.AppContainerSid = appcontainer_sid;
  ZeroMemory(capabilities, sizeof(capabilities));
  if (wcscmp(network, L"host") == 0) {
    if (!ConvertStringSidToSidW(L"S-1-15-3-1", &network_sid)) { print_last_error(L"ConvertStringSidToSidW"); goto cleanup; }
    if (!ConvertStringSidToSidW(L"S-1-15-3-3", &private_network_sid)) { print_last_error(L"ConvertStringSidToSidW private network"); goto cleanup; }
    capabilities[0].Sid = network_sid; capabilities[0].Attributes = SE_GROUP_ENABLED;
    capabilities[1].Sid = private_network_sid; capabilities[1].Attributes = SE_GROUP_ENABLED;
    security_capabilities.Capabilities = capabilities; security_capabilities.CapabilityCount = 2;
  }
  if (null_stdio ? !open_null_standard_handles(inherited_stdio) : !duplicate_standard_handles(inherited_stdio)) goto cleanup;
  if (debug_enabled()) fwprintf(stderr, L"CapLock AppContainer stdio handle types: stdin=%lu stdout=%lu stderr=%lu\n", (unsigned long)GetFileType(inherited_stdio[0]), (unsigned long)GetFileType(inherited_stdio[1]), (unsigned long)GetFileType(inherited_stdio[2]));
  InitializeProcThreadAttributeList(NULL, 2, 0, &attributes_size);
  attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributes_size);
  if (attributes == NULL || !InitializeProcThreadAttributeList(attributes, 2, 0, &attributes_size) ||
      !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security_capabilities, sizeof(security_capabilities), NULL, NULL) ||
      !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited_stdio, sizeof(inherited_stdio), NULL, NULL)) { print_last_error(L"AppContainer startup attributes"); goto cleanup; }
  command_line = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32768 * sizeof(wchar_t));
  if (command_line == NULL) goto cleanup;
  for (index = command_index; index < argc; index++) if (!append_argument(command_line, 32768, argv[index])) { fwprintf(stderr, L"caplock-sandbox: command line too long\n"); goto cleanup; }
  job = CreateJobObjectW(NULL, NULL);
  ZeroMemory(&limits, sizeof(limits)); limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == NULL || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { print_last_error(L"Job Object"); goto cleanup; }
  if (debug_enabled()) fwprintf(stderr, L"CapLock Job: limitFlags=0x%08lX activeProcessLimit=%lu activeProcessLimitSet=false killOnClose=true breakaway=false childProcessPolicy=absent inheritHandles=true startupAttributes=securityCapabilities,handleList\n", (unsigned long)limits.BasicLimitInformation.LimitFlags, (unsigned long)limits.BasicLimitInformation.ActiveProcessLimit);
  ZeroMemory(&startup, sizeof(startup)); startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = inherited_stdio[0]; startup.StartupInfo.hStdOutput = inherited_stdio[1]; startup.StartupInfo.hStdError = inherited_stdio[2]; startup.lpAttributeList = attributes;
  ZeroMemory(&child, sizeof(child));
  /* Do not log application paths or command lines: lifecycle commands can
     contain credentials. Failures below identify only the Win32 operation. */
  if (GetFileAttributesW(argv[command_index]) == INVALID_FILE_ATTRIBUTES) { print_last_error(L"GetFileAttributesW application"); goto cleanup; }
  if (GetFileAttributesW(cwd) == INVALID_FILE_ATTRIBUTES) { print_last_error(L"GetFileAttributesW currentDirectory"); goto cleanup; }
  child_environment = env_file != NULL ? read_child_environment(env_file) : GetEnvironmentStringsW();
  child_environment_inherited = env_file == NULL;
  if (child_environment == NULL) goto cleanup;
  if (!child_environment_inherited) {
    LARGE_INTEGER size; HANDLE file = CreateFileW(env_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) { if (GetFileSizeEx(file, &size)) debug_child_environment(child_environment, (SIZE_T)size.QuadPart); CloseHandle(file); }
  } else if (debug_enabled()) fwprintf(stderr, L"CapLock child environment block: mode=inherited\n");
  debug_launch_request(argv[command_index], cwd, child_environment_inherited);
  if (!CreateProcessW(argv[command_index], command_line, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
      child_environment, cwd, &startup.StartupInfo, &child)) { print_last_error(L"CreateProcessW AppContainer"); goto cleanup; }
  if (child_environment_inherited) FreeEnvironmentStringsW(child_environment); else VirtualFree(child_environment, 0, MEM_RELEASE); child_environment = NULL;
  if (selftest_running) selftest_status.processLaunched = TRUE;
  if (!child_is_appcontainer(child.hProcess)) { fwprintf(stderr, L"caplock-sandbox: child is not an AppContainer\n"); TerminateProcess(child.hProcess, 1); goto cleanup; }
  if (selftest_running) selftest_status.tokenIsAppContainer = TRUE;
  if (!AssignProcessToJobObject(job, child.hProcess)) { print_last_error(L"AssignProcessToJobObject"); TerminateProcess(child.hProcess, 1); goto cleanup; }
  if (ResumeThread(child.hThread) == (DWORD)-1) { print_last_error(L"ResumeThread"); goto cleanup; }
  { DWORD wait, elapsed = 0; BOOL nested_observed = FALSE, nested_exited = FALSE;
    do {
      DWORD slice = watchdog_ms == INFINITE ? 100 : (watchdog_ms - elapsed < 100 ? watchdog_ms - elapsed : 100);
      wait = WaitForSingleObject(child.hProcess, slice);
      { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting; if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)) { if (accounting.ActiveProcesses > 1) { if (selftest_running) selftest_status.nodeChildObserved = TRUE; if (!nested_observed && debug_enabled()) { fwprintf(stderr, L"CapLock debug nested process observed: active=%lu\n", (unsigned long)accounting.ActiveProcesses); nested_observed = TRUE; } } else if (nested_observed && !nested_exited && debug_enabled()) { fwprintf(stderr, L"CapLock debug nested process exited: active=%lu\n", (unsigned long)accounting.ActiveProcesses); nested_exited = TRUE; } } }
      if (wait != WAIT_TIMEOUT) break;
      /* An observation poll expiring is not a lifecycle timeout. Production
         has no native watchdog; its caller enforces the configured deadline. */
      if (watchdog_ms != INFINITE) elapsed += slice;
    } while (watchdog_ms == INFINITE || elapsed < watchdog_ms);
    if (wait != WAIT_OBJECT_0) { if (wait == WAIT_TIMEOUT) { debug_job_processes(job); if (selftest_running) selftest_status.watchdogFired = TRUE; TerminateJobObject(job, ERROR_TIMEOUT); WaitForSingleObject(child.hProcess, 1000); } SetLastError(wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT); print_last_error(L"WaitForSingleObject lifecycle parent"); goto cleanup; }
  }
  GetExitCodeProcess(child.hProcess, &exit_code);
  if (selftest_running) selftest_status.childExitCode = exit_code;
  if (selftest_running) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting; selftest_status.parentExited = TRUE; if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL) && accounting.ActiveProcesses == 0) selftest_status.jobClean = TRUE; }
  success = TRUE;

cleanup:
  if (child_environment != NULL) { if (child_environment_inherited) FreeEnvironmentStringsW(child_environment); else VirtualFree(child_environment, 0, MEM_RELEASE); }
  /* Closing a kill-on-close Job requests termination asynchronously. Drain it
     before restoring ACLs/returning, so JS cleanup cannot race live descendants
     holding staged executables or a cwd inside the owned temporary tree. */
  if (job != NULL) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    ULONGLONG deadline = GetTickCount64() + 3000;
    if (!TerminateJobObject(job, 1)) { print_last_error(L"TerminateJobObject cleanup"); success = FALSE; }
    for (;;) {
      if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)) { print_last_error(L"QueryInformationJobObject cleanup"); success = FALSE; break; }
      if (accounting.ActiveProcesses == 0) { if (selftest_running) selftest_status.jobClean = TRUE; break; }
      if (GetTickCount64() >= deadline) { SetLastError(ERROR_TIMEOUT); print_last_error(L"Job cleanup drain"); success = FALSE; break; }
      Sleep(10);
    }
    CloseHandle(job);
  }
  if (child.hProcess != NULL) {
    if (WaitForSingleObject(child.hProcess, 3000) != WAIT_OBJECT_0) { SetLastError(ERROR_TIMEOUT); print_last_error(L"Child cleanup wait"); success = FALSE; }
    CloseHandle(child.hProcess);
  }
  if (child.hThread != NULL) CloseHandle(child.hThread);
  if (command_line != NULL) HeapFree(GetProcessHeap(), 0, command_line);
  if (attributes != NULL) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes); }
  for (index = 0; index < 3; index++) if (inherited_stdio[index] != NULL) CloseHandle(inherited_stdio[index]);
  while (acl_count > 0) restore_acl(&acls[--acl_count]);
  if (network_sid != NULL) LocalFree(network_sid);
  if (private_network_sid != NULL) LocalFree(private_network_sid);
  if (appcontainer_sid != NULL) FreeSid(appcontainer_sid);
  if (profile_created) DeleteAppContainerProfile(profile_name);
  return success ? (int)exit_code : 1;
}
