import type { ProtectionOptions } from "./index";

export interface JsoProtectorPluginOptions extends ProtectionOptions {
  removeSourceMaps?: boolean;
}

declare function jsoProtector(options?: JsoProtectorPluginOptions): {
  name: "jso-protector";
  apply: "build";
  enforce: "post";
  configResolved(resolvedConfig: unknown): void;
  generateBundle(outputOptions: unknown, bundle: Record<string, unknown>): Promise<void>;
};

export { jsoProtector };
export default jsoProtector;
