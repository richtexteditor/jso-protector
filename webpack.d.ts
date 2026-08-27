import type { ProtectionOptions } from "./index";

export interface JsoProtectorWebpackPluginOptions extends ProtectionOptions {
  removeSourceMaps?: boolean;
}

declare class JsoProtectorWebpackPlugin {
  constructor(options?: JsoProtectorWebpackPluginOptions);
  apply(compiler: unknown): void;
}

export { JsoProtectorWebpackPlugin };
export default JsoProtectorWebpackPlugin;
