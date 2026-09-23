/* Minimal classic AppContainer launcher diagnostic. Intentionally independent of CapLock. */
#include <windows.h>
#include <winternl.h>
#include <userenv.h>
#include <stdio.h>
#include <wchar.h>

static void error(const wchar_t *stage) {
  DWORD code = GetLastError(); wchar_t *text = NULL;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0, (LPWSTR)&text, 0, NULL);
  wprintf(L"%ls: error=%lu message=%ls\n", stage, code, text == NULL ? L"unknown" : text);
  if (text != NULL) LocalFree(text);
}

static void architecture(const wchar_t *name, HANDLE process) {
  USHORT process_machine = 0, native_machine = 0;
  if (IsWow64Process2(process, &process_machine, &native_machine))
    wprintf(L"%ls: processMachine=0x%04X nativeMachine=0x%04X\n", name, process_machine, native_machine);
  else error(L"IsWow64Process2");
}

static void startup_context(void) {
  wchar_t username[256] = {0}; DWORD username_size = _countof(username), session = 0;
  HANDLE token = NULL; TOKEN_ELEVATION elevation = {0}; DWORD size = 0;
  RTL_OSVERSIONINFOW version = {0};
  typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
  RtlGetVersionFn rtl_get_version = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
  version.dwOSVersionInfoSize = sizeof(version);
  GetUserNameW(username, &username_size); ProcessIdToSessionId(GetCurrentProcessId(), &session);
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size); CloseHandle(token); }
  if (rtl_get_version != NULL) rtl_get_version(&version);
  wprintf(L"username=%ls pid=%lu session=%lu elevated=%s os=%lu.%lu build=%lu\n", username, GetCurrentProcessId(), session,
    elevation.TokenIsElevated ? L"true" : L"false", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
}

static BOOL launch(const wchar_t *label, const wchar_t *application, const wchar_t *command, STARTUPINFOEXW *si) {
  PROCESS_INFORMATION child = {0}; wchar_t line[1024] = {0}; HANDLE token = NULL; DWORD app_container = 0;
  wcscpy_s(line, _countof(line), command);
  wprintf(L"%ls: lpApplicationName=%ls lpCommandLine=%ls lpEnvironment=NULL lpCurrentDirectory=NULL flags=0x%08lX cb=%u\n",
    label, application == NULL ? L"NULL" : application, line, EXTENDED_STARTUPINFO_PRESENT, si->StartupInfo.cb);
  if (!CreateProcessW(application, line, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si->StartupInfo, &child)) { error(label); return FALSE; }
  wprintf(L"%ls: CreateProcessW=success pid=%lu\n", label, child.dwProcessId);
  architecture(L"child", child.hProcess);
  if (!OpenProcessToken(child.hProcess, TOKEN_QUERY, &token)) error(L"OpenProcessToken(child)");
  else {
    DWORD size = sizeof(app_container);
    if (GetTokenInformation(token, TokenIsAppContainer, &app_container, sizeof(app_container), &size)) wprintf(L"%ls: TokenIsAppContainer=%lu\n", label, app_container);
    else error(L"GetTokenInformation(TokenIsAppContainer)");
    CloseHandle(token);
  }
  WaitForSingleObject(child.hProcess, INFINITE); CloseHandle(child.hThread); CloseHandle(child.hProcess); return TRUE;
}

int wmain(void) {
  wchar_t system[MAX_PATH] = {0}, executable[MAX_PATH] = {0}, profile[128] = {0};
  PSID sid = NULL; HRESULT hr; SIZE_T bytes = 0; LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  SECURITY_CAPABILITIES sc = {0}; STARTUPINFOEXW si = {0}; BOOL a = FALSE, b = FALSE;
  BOOL profile_created = FALSE;
  startup_context();
  if (!GetSystemDirectoryW(system, _countof(system))) { error(L"GetSystemDirectoryW"); return 1; }
  swprintf_s(executable, _countof(executable), L"%ls\\whoami.exe", system);
  wprintf(L"helper architecture:\n"); architecture(L"helper", GetCurrentProcess());
  wprintf(L"target=%ls attributes=0x%08lX\n", executable, GetFileAttributesW(executable));
  if (GetFileAttributesW(executable) == INVALID_FILE_ATTRIBUTES) { error(L"GetFileAttributesW(target)"); return 1; }
  swprintf_s(profile, _countof(profile), L"CapLockDiagnostic-%lu-%lu-%lu", GetCurrentProcessId(), GetTickCount(), (unsigned long)(GetTickCount64() & 0xffffffffULL));
  wprintf(L"profile=%ls\n", profile);
  hr = CreateAppContainerProfile(profile, profile, L"CapLock AppContainer launch diagnostic", NULL, 0, &sid);
  if (FAILED(hr)) { wprintf(L"CreateAppContainerProfile: HRESULT=0x%08lX\n", (unsigned long)hr); return 1; }
  profile_created = TRUE; wprintf(L"CreateAppContainerProfile=success sid=%p\n", sid);
  sc.AppContainerSid = sid; sc.Capabilities = NULL; sc.CapabilityCount = 0; sc.Reserved = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
  attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
  if (attributes == NULL || !InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) { error(L"InitializeProcThreadAttributeList"); goto cleanup; }
  if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL)) { error(L"UpdateProcThreadAttribute(SECURITY_CAPABILITIES)"); goto cleanup; }
  si.StartupInfo.cb = sizeof(STARTUPINFOEXW); si.lpAttributeList = attributes;
  a = launch(L"form-A", NULL, executable, &si);
  b = launch(L"form-B", executable, executable, &si);
  wprintf(L"RESULT form-A=%s form-B=%s\n", a ? L"PASS" : L"FAIL", b ? L"PASS" : L"FAIL");
cleanup:
  if (attributes != NULL) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes); }
  if (sid != NULL) FreeSid(sid);
  if (profile_created) { hr = DeleteAppContainerProfile(profile); wprintf(L"DeleteAppContainerProfile: HRESULT=0x%08lX\n", (unsigned long)hr); }
  return (a || b) ? 0 : 1;
}
