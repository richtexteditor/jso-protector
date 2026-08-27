import type { ProtectionOptions } from "./index";

export interface JsoProtectorPluginOptions extends ProtectionOptions {
  removeSourceMaps?: boolean;
}

declare function jsoProtector(options?: JsoProtectorPluginOptions): {
  name: "jso-protector";
  setup(build: {
    initialOptions?: Record<string, unknown>;
    onEnd(callback: (result: { outputFiles?: unknown[] }) => void | Promise<void>): void;
  }): void;
};

export { jsoProtector };
export default jsoProtector;
