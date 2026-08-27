import type { JsoProtectorWebpackPluginOptions } from "./webpack";

export interface JsoProtectorNextOptions extends JsoProtectorWebpackPluginOptions {
  applyInDevelopment?: boolean;
  target?: "client" | "server" | "both";
}

export interface NextWebpackContextLike {
  dev?: boolean;
  isServer?: boolean;
}

export interface NextConfigLike {
  webpack?: (config: Record<string, unknown>, context: NextWebpackContextLike) => Record<string, unknown>;
  [key: string]: unknown;
}

declare function withJsoProtector(
  nextConfig?: NextConfigLike | ((...args: unknown[]) => NextConfigLike | Promise<NextConfigLike>),
  options?: JsoProtectorNextOptions
): NextConfigLike | ((...args: unknown[]) => Promise<NextConfigLike>);

export { withJsoProtector };
export default withJsoProtector;
