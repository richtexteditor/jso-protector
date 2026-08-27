import type { ProtectionOptions, ProtectionPlan, ProtectionRunResult, ResolvedProtectionConfig } from "./index";

export interface JsoProtectorTurbopackOptions extends ProtectionOptions {}

declare function protectTurbopackBuild(options?: JsoProtectorTurbopackOptions): Promise<ProtectionRunResult>;
declare function createTurbopackProtectionConfig(options?: JsoProtectorTurbopackOptions): ResolvedProtectionConfig;
declare function planTurbopackBuild(options?: JsoProtectorTurbopackOptions): ProtectionPlan;

export { createTurbopackProtectionConfig, planTurbopackBuild, protectTurbopackBuild };
export default protectTurbopackBuild;
