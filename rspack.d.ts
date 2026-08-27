import type { JsoProtectorWebpackPluginOptions } from "./webpack";

export interface JsoProtectorRspackPluginOptions extends JsoProtectorWebpackPluginOptions {}

declare class JsoProtectorRspackPlugin {
  constructor(options?: JsoProtectorRspackPluginOptions);
  apply(compiler: unknown): void;
}

export { JsoProtectorRspackPlugin };
export default JsoProtectorRspackPlugin;
