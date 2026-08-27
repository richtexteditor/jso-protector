import type { ProtectionOptions } from "./index";

export interface JsoProtectorPluginOptions extends ProtectionOptions {
  removeSourceMaps?: boolean;
}

declare function jsoProtector(options?: JsoProtectorPluginOptions): {
  name: "jso-protector";
  generateBundle(outputOptions: unknown, bundle: Record<string, unknown>): Promise<void>;
};

export { jsoProtector };
export default jsoProtector;
