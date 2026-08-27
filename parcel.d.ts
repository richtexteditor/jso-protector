import type { ProtectionOptions, ProtectionPlan, ProtectionRunResult, ResolvedProtectionConfig } from "./index";

export interface JsoProtectorParcelOptions extends ProtectionOptions {}

declare function protectParcelBuild(options?: JsoProtectorParcelOptions): Promise<ProtectionRunResult>;
declare function createParcelProtectionConfig(options?: JsoProtectorParcelOptions): ResolvedProtectionConfig;
declare function planParcelBuild(options?: JsoProtectorParcelOptions): ProtectionPlan;

export { createParcelProtectionConfig, planParcelBuild, protectParcelBuild };
export default protectParcelBuild;
