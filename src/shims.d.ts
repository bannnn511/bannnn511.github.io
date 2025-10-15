/**
 * TypeScript shims to appease diagnostics when compiling outside of Deno,
 * and when using std debounce, Promise.withResolvers, and import.meta.main.
 *
 * These are minimal ambient declarations intended only for type-checking.
 * They do not provide any runtime implementations.
 */

declare namespace Deno {
  /** Command-line arguments. */
  const args: string[];

  /** File system and process APIs (subset). */
  function readTextFile(path: string): Promise<string>;
  function readFile(path: string): Promise<Uint8Array>;
  function writeTextFile(path: string, data: string): Promise<void>;
  function writeTextFileSync(path: string, data: string): void;
  function writeFile(path: string, data: Uint8Array): Promise<void>;

  function remove(path: string, options?: { recursive?: boolean }): Promise<void>;
  function removeSync(path: string, options?: { recursive?: boolean }): void;

  function mkdir(path: string, options?: { recursive?: boolean }): Promise<void>;

  interface DirEntry {
    name: string;
    isFile: boolean;
    isDirectory: boolean;
    isSymlink: boolean;
  }
  function readDir(path: string): AsyncIterable<DirEntry>;

  interface FileSystemEvent {
    kind: string;
    paths: string[];
  }
  function watchFs(path: string, options?: { recursive?: boolean }): AsyncIterable<FileSystemEvent>;

  function execPath(): string;

  interface CommandOptions {
    args?: string[];
    cwd?: string;
    stdin?: "null" | "piped" | "inherit";
    stdout?: "null" | "piped" | "inherit";
    stderr?: "null" | "piped" | "inherit";
  }
  interface CommandOutput {
    success: boolean;
    code: number;
    stdout: Uint8Array;
    stderr: Uint8Array;
  }
  class Command {
    constructor(command: string, options?: CommandOptions);
    output(): Promise<CommandOutput>;
    outputSync(): CommandOutput;
  }

  namespace errors {
    class NotFound extends Error { }
  }

  function makeTempFile(options?: { dir?: string; prefix?: string; suffix?: string }): Promise<string>;
  function makeTempFileSync(options?: { dir?: string; prefix?: string; suffix?: string }): string;

  function rename(oldpath: string, newpath: string): Promise<void>;

  function exit(code?: number): never;
}

/**
 * Minimal types for the std debounce module import.
 * Usage in code: `import { debounce } from "@std/async/debounce";`
 */
declare module "@std/async/debounce" {
  export function debounce<T extends (...args: any[]) => any>(
    fn: T,
    delay: number,
  ): (...args: Parameters<T>) => Promise<void>;
}

/**
 * Global augmentations:
 * - Promise.withResolvers<T>()
 * - import.meta.main
 */
declare global {
  interface PromiseConstructor {
    withResolvers<T = unknown>(): {
      promise: Promise<T>;
      resolve: (value: T | PromiseLike<T>) => void;
      reject: (reason?: any) => void;
    };
  }

  interface ImportMeta {
    /** True if this module is the program entrypoint (Deno-specific). */
    readonly main?: boolean;
  }
}

/** Ensure this file is treated as a module for global augmentations above. */
export { };
