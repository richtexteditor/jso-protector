import type { ProtectionOptions } from "./index";

export interface JsoProtectorBrowserifyOptions extends ProtectionOptions {
  fileName?: string;
}

declare function jsoProtectorBrowserify(file: string, options?: JsoProtectorBrowserifyOptions): NodeJS.ReadWriteStream;

export { jsoProtectorBrowserify };
export default jsoProtectorBrowserify;
