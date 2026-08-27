import type { ProtectionOptions } from "./index";

export interface JsoProtectorWebpackLoaderOptions extends ProtectionOptions {
  fileName?: string;
}

declare function jsoProtectorLoader(
  this: unknown,
  source: string | Buffer,
  sourceMap?: unknown,
  meta?: unknown
): void;

export { jsoProtectorLoader };
export default jsoProtectorLoader;
