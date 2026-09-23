export type NetworkMode = "none" | "host";
export interface PackageIdentity { name: string; version: string; packageDir: string; packageJsonPath: string; integrity?: string }
export interface Lifecycle { event: "preinstall" | "install" | "postinstall"; command: string; hash: string }
export interface Policy { filesystem?: { read?: string[]; write?: string[] }; env?: { allow?: string[] }; network?: NetworkMode }
export interface LockEntry { package: { name: string; version: string; integrity?: string }; lifecycle: Lifecycle; policy: Required<Policy> }
export interface Lockfile { version: 1; packages: LockEntry[] }

/** Platform-neutral input passed to an OS enforcement backend. */
export interface SandboxCommand { executable: string; args: string[]; cwd?: string }
export interface SandboxContext { projectRoot: string; identity: PackageIdentity; traceFile?: string; timeoutMs?: number }
export interface SandboxCapabilities {
  filesystemIsolation: boolean; environmentIsolation: boolean; networkIsolation: boolean;
  processContainment: boolean; processObservation: boolean;
}
export interface SandboxAvailability { available: boolean; detail: string; capabilities: SandboxCapabilities }
export interface SandboxResult { code: number; stdout: string; stderr: string; executables?: string[] }
export interface DoctorCheck { name: string; ok: boolean; detail: string }
export interface SandboxBackend {
  readonly id: string;
  readonly platform: NodeJS.Platform;
  checkAvailability(): Promise<SandboxAvailability>;
  doctor(): Promise<DoctorCheck[]>;
  run(command: SandboxCommand, policy: Required<Policy>, context: SandboxContext): Promise<SandboxResult>;
}
