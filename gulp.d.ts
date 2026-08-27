import type { ProtectionOptions } from "./index";

export interface JsoProtectorGulpOptions extends ProtectionOptions {
  removeSourceMaps?: boolean;
}

declare function jsoProtector(options?: JsoProtectorGulpOptions): NodeJS.ReadWriteStream;

export { jsoProtector };
export default jsoProtector;
