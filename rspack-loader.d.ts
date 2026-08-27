import type { JsoProtectorWebpackLoaderOptions } from "./webpack-loader";

export interface JsoProtectorRspackLoaderOptions extends JsoProtectorWebpackLoaderOptions {}

declare function jsoProtectorRspackLoader(
  this: unknown,
  source: string | Buffer,
  sourceMap?: unknown,
  meta?: unknown
): void;

export { jsoProtectorRspackLoader };
export default jsoProtectorRspackLoader;
