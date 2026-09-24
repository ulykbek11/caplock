/* CapLock Windows sandbox helper. All security enforcement is native Win32. */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>
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
  static const wchar_t *wanted[] = { L"SystemRoot", L"WINDIR", L"ComSpec", L"PATH", L"PATHEXT", L"TEMP", L"TMP", L"USERPROFILE", L"HOME", L"HOMEDRIVE", L"HOMEPATH", L"LOCALAPPDATA", L"APPDATA" };
  SIZE_T index = 0, count = 0, chars = bytes / sizeof(wchar_t); BOOL well_formed = TRUE, sorted = TRUE; const wchar_t *previous = NULL;
  if (!debug_enabled()) return;
  while (index + 1 < chars && block[index] != L'\0') { wchar_t *entry = block + index, *equals = wcschr(entry, L'='); if (equals == NULL || equals == entry) well_formed = FALSE; if (previous != NULL && _wcsicmp(previous, entry) > 0) sorted = FALSE; previous = entry; count++; index += wcslen(entry) + 1; }
  fwprintf(stderr, L"CapLock child environment block: mode=custom entries=%zu chars=%zu doubleNul=%s validEntries=%s sortedCaseInsensitive=%s\n", count, chars, (chars >= 2 && block[chars - 1] == L'\0' && block[chars - 2] == L'\0') ? L"true" : L"false", well_formed ? L"true" : L"false", sorted ? L"true" : L"false");
  for (SIZE_T w = 0; w < _countof(wanted); w++) { BOOL found = FALSE; index = 0; while (index < chars && block[index] != L'\0') { size_t n = wcslen(wanted[w]); if (_wcsnicmp(block + index, wanted[w], n) == 0 && block[index + n] == L'=') { found = TRUE; break; } index += wcslen(block + index) + 1; } fwprintf(stderr, L"CapLock child environment: %ls=%ls\n", wanted[w], found ? L"present" : L"absent"); }
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

int wmain(int argc, wchar_t **argv) {
  const wchar_t *package_path = NULL, *temp_path = NULL, *cwd = NULL, *network = NULL, *env_file = NULL;
  const wchar_t *reads[MAX_GRANTS] = { NULL }, *writes[MAX_GRANTS] = { NULL };
  int read_count = 0, write_count = 0, command_index = -1, index;
  wchar_t profile_name[128], *command_line = NULL;
  PSID appcontainer_sid = NULL, network_sid = NULL, private_network_sid = NULL;
  SID_AND_ATTRIBUTES capabilities[2];
  SECURITY_CAPABILITIES security_capabilities;
  SIZE_T attributes_size = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  STARTUPINFOEXW startup;
  PROCESS_INFORMATION child;
  LPWCH child_environment = NULL;
  BOOL child_environment_inherited = FALSE;
  HANDLE job = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  SavedAcl acls[MAX_GRANTS + 2] = { 0 }; int acl_count = 0;
  BOOL profile_created = FALSE, success = FALSE;
  DWORD exit_code = 1;

  if (argc == 2 && wcscmp(argv[1], L"--help") == 0) { wprintf(L"Usage: caplock-sandbox --package DIR --temp DIR --cwd DIR --network none|host --env-file FILE [--read DIR] [--write DIR] -- EXECUTABLE [ARGS...]\n       caplock-sandbox --selftest\n"); return 0; }
  if (argc == 2 && wcscmp(argv[1], L"--selftest") == 0) return selftest();
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
    else if (wcscmp(argv[index], L"--read") == 0 && read_count < MAX_GRANTS) reads[read_count++] = argv[++index];
    else if (wcscmp(argv[index], L"--write") == 0 && write_count < MAX_GRANTS) writes[write_count++] = argv[++index];
    else { fwprintf(stderr, L"caplock-sandbox: invalid argument\n"); goto cleanup; }
  }
  if (package_path == NULL || temp_path == NULL || cwd == NULL || network == NULL || (!selftest_running && env_file == NULL) || command_index < 0 || command_index >= argc) {
    fwprintf(stderr, L"caplock-sandbox: --package, --temp, --cwd, --network, --env-file and command are required\n"); goto cleanup;
  }
  if (wcscmp(network, L"none") != 0 && wcscmp(network, L"host") != 0) { fwprintf(stderr, L"caplock-sandbox: invalid network mode\n"); goto cleanup; }
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
  InitializeProcThreadAttributeList(NULL, 1, 0, &attributes_size);
  attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributes_size);
  if (attributes == NULL || !InitializeProcThreadAttributeList(attributes, 1, 0, &attributes_size) ||
      !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security_capabilities, sizeof(security_capabilities), NULL, NULL)) { print_last_error(L"AppContainer startup attributes"); goto cleanup; }
  command_line = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32768 * sizeof(wchar_t));
  if (command_line == NULL) goto cleanup;
  for (index = command_index; index < argc; index++) if (!append_argument(command_line, 32768, argv[index])) { fwprintf(stderr, L"caplock-sandbox: command line too long\n"); goto cleanup; }
  job = CreateJobObjectW(NULL, NULL);
  ZeroMemory(&limits, sizeof(limits)); limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == NULL || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { print_last_error(L"Job Object"); goto cleanup; }
  ZeroMemory(&startup, sizeof(startup)); startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes;
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
  if (!CreateProcessW(argv[command_index], command_line, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
      child_environment, cwd, &startup.StartupInfo, &child)) { print_last_error(L"CreateProcessW AppContainer"); goto cleanup; }
  if (child_environment_inherited) FreeEnvironmentStringsW(child_environment); else VirtualFree(child_environment, 0, MEM_RELEASE); child_environment = NULL;
  if (selftest_running) selftest_status.processLaunched = TRUE;
  if (!child_is_appcontainer(child.hProcess)) { fwprintf(stderr, L"caplock-sandbox: child is not an AppContainer\n"); TerminateProcess(child.hProcess, 1); CloseHandle(child.hThread); CloseHandle(child.hProcess); goto cleanup; }
  if (selftest_running) selftest_status.tokenIsAppContainer = TRUE;
  if (!AssignProcessToJobObject(job, child.hProcess)) { print_last_error(L"AssignProcessToJobObject"); TerminateProcess(child.hProcess, 1); CloseHandle(child.hThread); CloseHandle(child.hProcess); goto cleanup; }
  ResumeThread(child.hThread); WaitForSingleObject(child.hProcess, INFINITE); GetExitCodeProcess(child.hProcess, &exit_code);
  if (selftest_running) selftest_status.childExitCode = exit_code;
  CloseHandle(child.hThread); CloseHandle(child.hProcess); success = TRUE;

cleanup:
  if (child_environment != NULL) { if (child_environment_inherited) FreeEnvironmentStringsW(child_environment); else VirtualFree(child_environment, 0, MEM_RELEASE); }
  if (job != NULL) CloseHandle(job);
  if (command_line != NULL) HeapFree(GetProcessHeap(), 0, command_line);
  if (attributes != NULL) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes); }
  while (acl_count > 0) restore_acl(&acls[--acl_count]);
  if (network_sid != NULL) LocalFree(network_sid);
  if (private_network_sid != NULL) LocalFree(private_network_sid);
  if (appcontainer_sid != NULL) FreeSid(appcontainer_sid);
  if (profile_created) DeleteAppContainerProfile(profile_name);
  return success ? (int)exit_code : 1;
}
