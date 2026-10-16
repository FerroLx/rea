/**
 * A versioned, curated mapping from imported Windows APIs to behaviour
 * categories and MITRE ATT&CK technique IDs. API names come from Microsoft's
 * public API documentation and technique IDs from MITRE ATT&CK; both are facts.
 * No third-party rule text is vendored.
 *
 * Every entry carries a confidence tier so a consumer (for example an LLM
 * triage step) can weigh signals: `strong` APIs are rarely imported without the
 * behaviour, `medium` ones are suggestive, and `weak` ones are routinely
 * imported by ordinary software (some by the C runtime itself).
 * `argumentDependent` marks APIs whose meaning depends on an argument that
 * static import analysis cannot see. Matching reports "imports consistent
 * with" a behaviour, never that the binary performs it.
 */

export const BINARY_IMPORT_TAXONOMY_VERSION = "1.0.1";

export type ImportConfidence = "strong" | "medium" | "weak";

export interface ImportTaxonomyEntry {
  readonly api: string;
  readonly category: string;
  readonly attack: readonly string[];
  readonly confidence: ImportConfidence;
  readonly argumentDependent?: true;
}

/** Categories reported by default; the rest are opt-in (ubiquitous, noisy). */
export const DEFAULT_IMPORT_CATEGORIES: readonly string[] = [
  "process_injection",
  "process_creation",
  "persistence_registry",
  "service_control",
  "keyboard_capture",
  "screen_capture",
  "clipboard",
  "credential_access",
  "anti_debug",
  "privilege",
  "download",
  "network",
  "crypto",
  "dynamic_resolution",
  "driver_loading",
];

export const OPT_IN_IMPORT_CATEGORIES: readonly string[] = ["file_enumeration"];

const e = (
  category: string,
  attack: readonly string[],
  confidence: ImportConfidence,
  apis: readonly string[],
  argumentDependent = false,
): ImportTaxonomyEntry[] =>
  apis.map((api) => ({
    api,
    category,
    attack,
    confidence,
    ...(argumentDependent ? { argumentDependent: true as const } : {}),
  }));

/**
 * Entries keyed by exact API name. Where Windows exports A/W variants, both are
 * listed. Process injection keeps the bare T1055: imports alone do not
 * determine the sub-technique.
 */
export const BINARY_IMPORT_TAXONOMY: readonly ImportTaxonomyEntry[] = [
  ...e("process_injection", ["T1055"], "strong", [
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "NtQueueApcThread",
    "NtMapViewOfSection",
  ]),
  // SetThreadContext is imported by every Windows Go runtime (goroutine
  // preemption) and by debuggers; QueueUserAPC by ordinary thread-wakeup code.
  // Both are injection primitives but not rare without injection.
  ...e("process_injection", ["T1055"], "medium", [
    "SetThreadContext",
    "QueueUserAPC",
    "VirtualAllocEx",
    "VirtualProtectEx",
    "NtAllocateVirtualMemory",
  ]),
  // Process monitors, debuggers and installers open other processes routinely;
  // alone it gave 25 benign tools a medium injection signal.
  ...e("process_injection", ["T1055"], "weak", ["OpenProcess"]),
  ...e("process_creation", ["T1106"], "weak", [
    "CreateProcessA",
    "CreateProcessW",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
  ]),
  ...e(
    "persistence_registry",
    ["T1547.001"],
    "medium",
    [
      "RegSetValueExA",
      "RegSetValueExW",
      "RegCreateKeyExA",
      "RegCreateKeyExW",
      "RegSetKeyValueA",
      "RegSetKeyValueW",
    ],
    true,
  ),
  ...e("service_control", ["T1543.003"], "strong", [
    "CreateServiceA",
    "CreateServiceW",
    "ChangeServiceConfigA",
    "ChangeServiceConfigW",
    "ChangeServiceConfig2A",
    "ChangeServiceConfig2W",
  ]),
  ...e("service_control", ["T1543.003"], "weak", [
    "OpenSCManagerA",
    "OpenSCManagerW",
    "StartServiceA",
    "StartServiceW",
  ]),
  ...e(
    "keyboard_capture",
    ["T1056.001"],
    "medium",
    ["SetWindowsHookExA", "SetWindowsHookExW", "RegisterRawInputDevices"],
    true,
  ),
  ...e(
    "keyboard_capture",
    ["T1056.001"],
    "weak",
    ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"],
    true,
  ),
  ...e("screen_capture", ["T1113"], "weak", [
    "BitBlt",
    "GetDC",
    "GetWindowDC",
    "CreateCompatibleDC",
    "CreateCompatibleBitmap",
  ]),
  ...e("clipboard", ["T1115"], "weak", ["GetClipboardData", "OpenClipboard"]),
  ...e(
    "credential_access",
    ["T1003.001"],
    "medium",
    ["MiniDumpWriteDump"],
    true,
  ),
  ...e("credential_access", ["T1555"], "medium", [
    "CredEnumerateA",
    "CredEnumerateW",
    "CredReadA",
    "CredReadW",
  ]),
  ...e("credential_access", ["T1003"], "strong", [
    "LsaRetrievePrivateData",
    "SamIConnect",
  ]),
  ...e("anti_debug", ["T1622"], "medium", [
    "CheckRemoteDebuggerPresent",
    "NtSetInformationThread",
  ]),
  ...e("anti_debug", ["T1622"], "weak", [
    "IsDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
  ]),
  ...e("privilege", ["T1134"], "medium", [
    "AdjustTokenPrivileges",
    "ImpersonateLoggedOnUser",
    "DuplicateTokenEx",
    "SetTokenInformation",
  ]),
  ...e("privilege", ["T1134"], "weak", [
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    "LookupPrivilegeValueW",
  ]),
  ...e("download", ["T1105"], "strong", [
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "URLDownloadToCacheFileA",
    "URLDownloadToCacheFileW",
  ]),
  ...e("network", ["T1071"], "weak", [
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetReadFile",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WinHttpOpen",
    "WinHttpSendRequest",
    "WinHttpReadData",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
  ]),
  ...e(
    "crypto",
    ["T1027", "T1486"],
    "weak",
    [
      "CryptEncrypt",
      "CryptDecrypt",
      "CryptAcquireContextA",
      "CryptAcquireContextW",
      "BCryptEncrypt",
      "BCryptDecrypt",
    ],
    true,
  ),
  ...e("dynamic_resolution", ["T1027.007"], "weak", [
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "LdrGetProcedureAddress",
    "LdrLoadDll",
  ]),
  ...e("driver_loading", ["T1543.003", "T1014"], "strong", [
    "NtLoadDriver",
    "ZwLoadDriver",
  ]),
  ...e("driver_loading", ["T1543.003"], "weak", ["DeviceIoControl"], true),
  ...e("file_enumeration", ["T1083"], "weak", [
    "FindFirstFileA",
    "FindFirstFileW",
    "FindFirstFileExA",
    "FindFirstFileExW",
    "FindNextFileA",
    "FindNextFileW",
  ]),
];

const BY_API = new Map(
  BINARY_IMPORT_TAXONOMY.map((entry) => [entry.api, entry]),
);

/** The taxonomy entry for an exact imported API name, if any. */
export const importTaxonomyEntry = (
  api: string,
): ImportTaxonomyEntry | undefined => BY_API.get(api);

/** The runtime-resolution APIs (their import is itself a hint). */
export const RESOLVER_APIS: ReadonlySet<string> = new Set([
  "GetProcAddress",
  "LoadLibraryA",
  "LoadLibraryW",
  "LoadLibraryExA",
  "LoadLibraryExW",
  "LdrGetProcedureAddress",
  "LdrLoadDll",
]);
