/* Native npm script-shell launcher for Node 24 on Windows.
 * Node/npm cannot spawn a .cmd script-shell directly (EINVAL/DEP0190), so the
 * shim is an .exe. It launches the trusted sibling dist/shell.js with Node.
 */
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static BOOL append_quoted(wchar_t *out, size_t capacity, const wchar_t *arg) {
  size_t n = wcslen(out), i = 0, slashes = 0;
  if (n + 3 >= capacity) return FALSE;
  if (n) out[n++] = L' ';
  out[n++] = L'"'; out[n] = 0;
  for (; arg[i]; i++) {
    if (arg[i] == L'\\') { slashes++; continue; }
    while (slashes) { if (n + 1 >= capacity) return FALSE; out[n++] = L'\\'; slashes--; }
    if (arg[i] == L'"') { if (n + 2 >= capacity) return FALSE; out[n++] = L'\\'; out[n++] = L'"'; }
    else { if (n + 1 >= capacity) return FALSE; out[n++] = arg[i]; }
  }
  while (slashes) { if (n + 2 >= capacity) return FALSE; out[n++] = L'\\'; out[n++] = L'\\'; slashes--; }
  if (n + 2 >= capacity) return FALSE;
  out[n++] = L'"'; out[n] = 0; return TRUE;
}

static void diagnostics(int argc, wchar_t **argv, const wchar_t *script) {
  wchar_t cwd[MAX_PATH] = L"";
  GetCurrentDirectoryW(_countof(cwd), cwd);
  fwprintf(stderr, L"caplock-shell diagnostic: argc=%d cwd=%ls shellJs=%ls\n", argc, cwd, script);
  for (int i = 0; i < argc; i++) fwprintf(stderr, L"caplock-shell diagnostic: argv[%d]=<%zu chars>\n", i, wcslen(argv[i]));
  fwprintf(stderr, L"caplock-shell diagnostic: npm_lifecycle_event=%s npm_lifecycle_script=%s npm_package_json=%s npm_package_name=%s npm_package_version=%s\n",
    GetEnvironmentVariableW(L"npm_lifecycle_event", NULL, 0) ? L"present" : L"absent",
    GetEnvironmentVariableW(L"npm_lifecycle_script", NULL, 0) ? L"present" : L"absent",
    GetEnvironmentVariableW(L"npm_package_json", NULL, 0) ? L"present" : L"absent",
    GetEnvironmentVariableW(L"npm_package_name", NULL, 0) ? L"present" : L"absent",
    GetEnvironmentVariableW(L"npm_package_version", NULL, 0) ? L"present" : L"absent");
}

int wmain(int argc, wchar_t **argv) {
  wchar_t node[MAX_PATH], executable[MAX_PATH], script[MAX_PATH], command[32768] = L"";
  DWORD node_length = GetEnvironmentVariableW(L"CAPLOCK_NODE", node, MAX_PATH);
  if (!node_length || node_length >= MAX_PATH) { fwprintf(stderr, L"caplock-shell: CAPLOCK_NODE is required.\n"); diagnostics(argc, argv, L"<unresolved>"); return 1; }
  DWORD length = GetModuleFileNameW(NULL, executable, MAX_PATH);
  if (!length || length >= MAX_PATH) { fwprintf(stderr, L"caplock-shell: unable to locate launcher.\n"); diagnostics(argc, argv, L"<unresolved>"); return 1; }
  wchar_t *bin = wcsrchr(executable, L'\\'); if (!bin) return 1; *bin = 0;
  _snwprintf_s(script, MAX_PATH, _TRUNCATE, L"%ls\\..\\..\\dist\\shell.js", executable);
  if (GetFileAttributesW(script) == INVALID_FILE_ATTRIBUTES) { fwprintf(stderr, L"caplock-shell: trusted shell entry point is missing (%lu).\n", GetLastError()); diagnostics(argc, argv, script); return 1; }
  if (!append_quoted(command, _countof(command), node) || !append_quoted(command, _countof(command), script)) { diagnostics(argc, argv, script); return 1; }
  for (int i = 1; i < argc; i++) if (!append_quoted(command, _countof(command), argv[i])) { diagnostics(argc, argv, script); return 1; }
  STARTUPINFOW startup = { sizeof(startup) }; PROCESS_INFORMATION child = { 0 };
  if (!CreateProcessW(node, command, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &startup, &child)) {
    fwprintf(stderr, L"caplock-shell: could not launch trusted Node runtime (%lu).\n", GetLastError()); diagnostics(argc, argv, script); return 1;
  }
  WaitForSingleObject(child.hProcess, INFINITE); DWORD code = 1; GetExitCodeProcess(child.hProcess, &code);
  CloseHandle(child.hThread); CloseHandle(child.hProcess);
  if (code != 0) { fwprintf(stderr, L"caplock-shell: trusted JS shell exited with %lu.\n", code); diagnostics(argc, argv, script); }
  return (int)code;
}
