import type { ProtectionOptions, ProtectionPlan, ProtectionRunResult, ResolvedProtectionConfig } from "./index";

export interface JsoProtectorBunOptions extends ProtectionOptions {}

declare function protectBunBuild(options?: JsoProtectorBunOptions): Promise<ProtectionRunResult>;
declare function createBunProtectionConfig(options?: JsoProtectorBunOptions): ResolvedProtectionConfig;
declare function planBunBuild(options?: JsoProtectorBunOptions): ProtectionPlan;

export { createBunProtectionConfig, planBunBuild, protectBunBuild };
export default protectBunBuild;
