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

static BOOL grant_appcontainer_access(const wchar_t *path, PSID sid, DWORD access, SavedAcl *saved) {
  DWORD status;
  EXPLICIT_ACCESSW entry;
  PACL replacement = NULL;
  ZeroMemory(saved, sizeof(*saved));
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

static int selftest(void) {
  wchar_t root[MAX_PATH], package[MAX_PATH], temp[MAX_PATH], marker[MAX_PATH], system[MAX_PATH], command[2 * MAX_PATH];
  wchar_t *args[14]; DWORD length;
  length = GetTempPathW(_countof(root), root); if (length == 0 || length >= _countof(root)) return 1;
  if (!GetTempFileNameW(root, L"clk", 0, root)) return 1;
  DeleteFileW(root); if (!CreateDirectoryW(root, NULL)) return 1;
  swprintf_s(package, _countof(package), L"%ls\\package", root); swprintf_s(temp, _countof(temp), L"%ls\\temp", root); swprintf_s(marker, _countof(marker), L"%ls\\marker", package);
  if (!CreateDirectoryW(package, NULL) || !CreateDirectoryW(temp, NULL) || !GetSystemDirectoryW(system, _countof(system))) { RemoveDirectoryW(root); return 1; }
  swprintf_s(command, _countof(command), L"echo caplock-selftest > \"%ls\"", marker);
  args[0] = L"caplock-sandbox"; args[1] = L"--package"; args[2] = package; args[3] = L"--temp"; args[4] = temp; args[5] = L"--cwd"; args[6] = package; args[7] = L"--network"; args[8] = L"none"; args[9] = L"--"; args[10] = L"C:\\Windows\\System32\\cmd.exe"; args[11] = L"/d"; args[12] = L"/s"; args[13] = L"/c";
  /* cmd's command is intentionally supplied as the final mutable argument. */
  { wchar_t *full_args[15]; int code; BOOL allowed, cleanup;
    CopyMemory(full_args, args, sizeof(args)); full_args[14] = command;
    ZeroMemory(&selftest_status, sizeof(selftest_status)); selftest_running = TRUE;
    code = wmain(15, full_args); selftest_running = FALSE;
    allowed = GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES;
    DeleteFileW(marker); RemoveDirectoryW(temp); RemoveDirectoryW(package); cleanup = RemoveDirectoryW(root);
    wprintf(L"{\"profileCreated\":%s,\"processLaunched\":%s,\"tokenIsAppContainer\":%s,\"allowedWrite\":%s,\"cleanup\":%s}\n",
      selftest_status.profileCreated ? L"true" : L"false", selftest_status.processLaunched ? L"true" : L"false",
      selftest_status.tokenIsAppContainer ? L"true" : L"false", allowed ? L"true" : L"false", cleanup ? L"true" : L"false");
    return (code == 0 && selftest_status.profileCreated && selftest_status.processLaunched && selftest_status.tokenIsAppContainer && allowed && cleanup) ? 0 : 1; }
}

int wmain(int argc, wchar_t **argv) {
  const wchar_t *package_path = NULL, *temp_path = NULL, *cwd = NULL, *network = NULL;
  const wchar_t *reads[MAX_GRANTS] = { NULL }, *writes[MAX_GRANTS] = { NULL };
  int read_count = 0, write_count = 0, command_index = -1, index;
  wchar_t profile_name[128], *command_line = NULL;
  PSID appcontainer_sid = NULL, network_sid = NULL;
  SID_AND_ATTRIBUTES capability;
  SECURITY_CAPABILITIES security_capabilities;
  SIZE_T attributes_size = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  STARTUPINFOEXW startup;
  PROCESS_INFORMATION child;
  HANDLE job = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  SavedAcl acls[MAX_GRANTS + 2] = { 0 }; int acl_count = 0;
  BOOL profile_created = FALSE, success = FALSE;
  DWORD exit_code = 1;

  if (argc == 2 && wcscmp(argv[1], L"--help") == 0) { wprintf(L"Usage: caplock-sandbox --package DIR --temp DIR --cwd DIR --network none|host [--read DIR] [--write DIR] -- EXECUTABLE [ARGS...]\n       caplock-sandbox --selftest\n"); return 0; }
  if (argc == 2 && wcscmp(argv[1], L"--selftest") == 0) return selftest();

  for (index = 1; index < argc; index++) {
    if (wcscmp(argv[index], L"--") == 0) { command_index = index + 1; break; }
    if (index + 1 >= argc) { fwprintf(stderr, L"caplock-sandbox: missing value\n"); goto cleanup; }
    if (wcscmp(argv[index], L"--package") == 0) package_path = argv[++index];
    else if (wcscmp(argv[index], L"--temp") == 0) temp_path = argv[++index];
    else if (wcscmp(argv[index], L"--cwd") == 0) cwd = argv[++index];
    else if (wcscmp(argv[index], L"--network") == 0) network = argv[++index];
    else if (wcscmp(argv[index], L"--read") == 0 && read_count < MAX_GRANTS) reads[read_count++] = argv[++index];
    else if (wcscmp(argv[index], L"--write") == 0 && write_count < MAX_GRANTS) writes[write_count++] = argv[++index];
    else { fwprintf(stderr, L"caplock-sandbox: invalid argument\n"); goto cleanup; }
  }
  if (package_path == NULL || temp_path == NULL || cwd == NULL || network == NULL || command_index < 0 || command_index >= argc) {
    fwprintf(stderr, L"caplock-sandbox: --package, --temp, --cwd, --network and command are required\n"); goto cleanup;
  }
  if (wcscmp(network, L"none") != 0 && wcscmp(network, L"host") != 0) { fwprintf(stderr, L"caplock-sandbox: invalid network mode\n"); goto cleanup; }
  if (!CreateDirectoryW(temp_path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { print_last_error(L"CreateDirectoryW"); goto cleanup; }

  swprintf_s(profile_name, _countof(profile_name), L"CapLock-%lu-%lu-%lu", GetCurrentProcessId(), GetTickCount(), (unsigned long)(GetTickCount64() & 0xffffffffULL));
  if (FAILED(CreateAppContainerProfile(profile_name, profile_name, L"CapLock temporary sandbox", NULL, 0, &appcontainer_sid))) { fwprintf(stderr, L"caplock-sandbox: cannot create unique AppContainer profile\n"); goto cleanup; }
  profile_created = TRUE;
  if (selftest_running) selftest_status.profileCreated = TRUE;
  if (!grant_appcontainer_access(package_path, appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;
  if (!grant_appcontainer_access(temp_path, appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;
  for (index = 0; index < read_count; index++) if (!grant_appcontainer_access(reads[index], appcontainer_sid, GENERIC_READ | GENERIC_EXECUTE, &acls[acl_count++])) goto cleanup;
  for (index = 0; index < write_count; index++) if (!grant_appcontainer_access(writes[index], appcontainer_sid, GENERIC_ALL, &acls[acl_count++])) goto cleanup;

  ZeroMemory(&security_capabilities, sizeof(security_capabilities)); security_capabilities.AppContainerSid = appcontainer_sid;
  ZeroMemory(&capability, sizeof(capability));
  if (wcscmp(network, L"host") == 0) {
    if (!ConvertStringSidToSidW(L"S-1-15-3-1", &network_sid)) { print_last_error(L"ConvertStringSidToSidW"); goto cleanup; }
    capability.Sid = network_sid; capability.Attributes = SE_GROUP_ENABLED;
    security_capabilities.Capabilities = &capability; security_capabilities.CapabilityCount = 1;
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
  fwprintf(stderr, L"caplock-sandbox: application=%ls\ncaplock-sandbox: commandLine=%ls\ncaplock-sandbox: currentDirectory=%ls\n", argv[command_index], command_line, cwd);
  if (GetFileAttributesW(argv[command_index]) == INVALID_FILE_ATTRIBUTES) { print_last_error(L"GetFileAttributesW application"); goto cleanup; }
  if (GetFileAttributesW(cwd) == INVALID_FILE_ATTRIBUTES) { print_last_error(L"GetFileAttributesW currentDirectory"); goto cleanup; }
  if (!CreateProcessW(argv[command_index], command_line, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
      NULL, cwd, &startup.StartupInfo, &child)) { print_last_error(L"CreateProcessW AppContainer"); goto cleanup; }
  if (selftest_running) selftest_status.processLaunched = TRUE;
  if (!child_is_appcontainer(child.hProcess)) { fwprintf(stderr, L"caplock-sandbox: child is not an AppContainer\n"); TerminateProcess(child.hProcess, 1); CloseHandle(child.hThread); CloseHandle(child.hProcess); goto cleanup; }
  if (selftest_running) selftest_status.tokenIsAppContainer = TRUE;
  if (!AssignProcessToJobObject(job, child.hProcess)) { print_last_error(L"AssignProcessToJobObject"); TerminateProcess(child.hProcess, 1); CloseHandle(child.hThread); CloseHandle(child.hProcess); goto cleanup; }
  ResumeThread(child.hThread); WaitForSingleObject(child.hProcess, INFINITE); GetExitCodeProcess(child.hProcess, &exit_code);
  CloseHandle(child.hThread); CloseHandle(child.hProcess); success = TRUE;

cleanup:
  if (job != NULL) CloseHandle(job);
  if (command_line != NULL) HeapFree(GetProcessHeap(), 0, command_line);
  if (attributes != NULL) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes); }
  while (acl_count > 0) restore_acl(&acls[--acl_count]);
  if (network_sid != NULL) LocalFree(network_sid);
  if (appcontainer_sid != NULL) FreeSid(appcontainer_sid);
  if (profile_created) DeleteAppContainerProfile(profile_name);
  return success ? (int)exit_code : 1;
}
