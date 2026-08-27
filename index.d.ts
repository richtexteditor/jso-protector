export type PresetName = "standard" | "balanced" | "maximum";
export type InitTemplateName = "browser-app" | "html-app" | "node-app" | "electron-app" | "nextjs-app" | "vite-app" | "parcel-app" | "bun-app" | "browserify-app" | "webpack-app" | "rspack-app" | "turbopack-app" | "react-native-app";

export interface ProtectionOptions {
  config?: string;
  configFile?: string;
  mode?: string | null;
  javascriptObfuscatorOptions?: JavascriptObfuscatorCompatibilityOptions;
  jsConfuserOptions?: JsConfuserCompatibilityOptions;
  compact?: boolean;
  controlFlowFlattening?: boolean;
  debugProtection?: boolean;
  debugProtectionInterval?: number;
  debugProtectionIntervalMilliseconds?: number;
  deadCodeInjection?: boolean;
  deadCodeInjectionThreshold?: number;
  disableConsoleOutput?: boolean;
  domainLock?: string | string[];
  domainLockRedirectUrl?: string;
  forceTransformStrings?: string[];
  identifiersDictionary?: string[];
  identifiersPrefix?: string;
  identifierNamesGenerator?: string;
  identifierNamesCache?: Record<string, unknown> | null;
  identifierNamesCachePath?: string;
  inputFileName?: string;
  log?: boolean;
  numbersToExpressions?: boolean;
  optionsPreset?: string;
  parseHtml?: boolean;
  renameGlobals?: boolean;
  renameProperties?: boolean;
  renamePropertiesMode?: string;
  reservedStrings?: string[];
  seed?: string | number;
  selfDefending?: boolean;
  selfDefendingIntervalSeconds?: number;
  selfHealing?: boolean;
  selfHealingMaxAttempts?: number;
  antiMonkeyPatching?: boolean;
  antiMonkeyPatchingCleanRealm?: boolean;
  antiMonkeyPatchingIncludeGlobals?: string;
  antiMonkeyPatchingExcludeGlobals?: string;
  runtimeDefenseAction?: "throw" | "blank" | "redirect" | "reload" | "callback" | "degrade";
  runtimeDefenseCallback?: string;
  runtimeDefenseRedirectUrl?: string;
  simplify?: boolean;
  sourceMap?: boolean;
  sourceMapBaseUrl?: string;
  sourceMapFileName?: string;
  sourceMapMode?: string;
  sourceMapSourcesMode?: string;
  strictMode?: boolean | null;
  splitStrings?: boolean;
  splitStringsChunkLength?: number;
  stringArray?: boolean;
  stringArrayCallsTransform?: boolean;
  stringArrayCallsTransformThreshold?: number;
  stringArrayEncoding?: string | string[];
  stringArrayIndexShift?: boolean;
  stringArrayShuffle?: boolean;
  stringArrayRotate?: boolean;
  stringArrayIndexesType?: "hexadecimal-number" | "hexadecimal-numeric-string" | Array<"hexadecimal-number" | "hexadecimal-numeric-string">;
  stringArrayCallsTransform?: boolean;
  stringArrayCallsTransformThreshold?: number;
  stringArrayIndexesType?: string | string[];
  stringArrayRotate?: boolean;
  stringArrayIndexesType?: "hexadecimal-number" | "hexadecimal-numeric-string" | Array<"hexadecimal-number" | "hexadecimal-numeric-string">;
  stringArrayCallsTransform?: boolean;
  stringArrayCallsTransformThreshold?: number;
  stringArrayShuffle?: boolean;
  stringArrayRotate?: boolean;
  stringArrayThreshold?: number;
  stringArrayWrappersChainedCalls?: boolean;
  stringArrayWrappersCount?: number;
  stringArrayWrappersParametersMaxCount?: number;
  stringArrayWrappersType?: "variable" | "function";
  transformObjectKeys?: boolean;
  target?: string;
  transformObjectKeys?: boolean;
  unicodeEscapeSequence?: boolean;
  ignoreImports?: boolean;
  endpoint?: string;
  apiKey?: string;
  apiPassword?: string;
  projectName?: string;
  input?: string;
  output?: string;
  preset?: PresetName;
  webPreset?: string;
  include?: string[];
  extensions?: string[];
  markupExtensions?: string[];
  exclude?: string[];
  assetExclude?: string[];
  copyAssets?: boolean;
  mixedServer?: boolean;
  removeSourceMaps?: boolean;
  honorConditionalComments?: boolean;
  protectMarkedComments?: boolean;
  keepHeaderComment?: boolean;
  protectObjectDeclaration?: boolean;
  moveNestedFunction?: boolean;
  formattedOutput?: boolean;
  keepIndent?: boolean;
  lineNumbers?: boolean;
  lockDomainSubdomains?: boolean;
  lockDomainMessage?: string;
  lockDate?: boolean;
  lockDateValue?: string;
  lockDateMessage?: string;
  jsConfuserLockAntiDebug?: boolean | number;
  jsConfuserLockIntegrity?: boolean | number;
  jsConfuserLockSelfDefending?: boolean | number;
  jsConfuserLockStartDate?: string;
  jsConfuserLockCountermeasures?: string;
  jsConfuserLockTamperProtection?: boolean | number;
  reservedNames?: string[];
  variableExclusion?: string;
  manifest?: string;
  maxOutputBytes?: number;
  maxGrowthRatio?: number;
  options?: Record<string, unknown>;
}

export interface JsConfuserLockCompatibilityOptions {
  antiDebug?: boolean | number;
  countermeasures?: unknown;
  customLocks?: unknown;
  domainLock?: string | string[];
  endDate?: string | Date;
  integrity?: boolean | number;
  selfDefending?: boolean | number;
  startDate?: string | Date;
  tamperProtection?: boolean | number;
}

export interface JsConfuserCompatibilityOptions {
  astScrambler?: boolean | number;
  calculator?: boolean | number;
  compact?: boolean;
  controlFlowFlattening?: boolean | number;
  deadCode?: boolean | number;
  dispatcher?: boolean | number;
  duplicateLiteralsRemoval?: boolean | number;
  flatten?: boolean | number;
  globalConcealing?: boolean | number;
  hexadecimalNumbers?: boolean | number;
  identifierGenerator?: string;
  lock?: JsConfuserLockCompatibilityOptions;
  minify?: boolean;
  movedDeclarations?: boolean | number;
  objectExtraction?: boolean | number;
  opaquePredicates?: boolean | number;
  pack?: boolean | number | string;
  preserveFunctionLength?: boolean;
  preset?: "low" | "medium" | "high" | string;
  renameGlobals?: boolean | number;
  renameLabels?: boolean | number;
  renameVariables?: boolean | number;
  rgf?: boolean | number;
  shuffle?: boolean | number;
  stringCompression?: boolean | number;
  stringConcealing?: boolean | number;
  stringEncoding?: boolean | number | ((value: string) => boolean);
  stringSplitting?: boolean | number | ((value: string) => boolean);
  target?: "browser" | "node" | string;
  variableMasking?: boolean | number;
}

export interface JavascriptObfuscatorCompatibilityOptions {
  compact?: boolean;
  controlFlowFlattening?: boolean;
  debugProtection?: boolean;
  debugProtectionInterval?: number;
  deadCodeInjection?: boolean;
  deadCodeInjectionThreshold?: number;
  disableConsoleOutput?: boolean;
  domainLock?: string | string[];
  domainLockRedirectUrl?: string;
  forceTransformStrings?: string[];
  identifiersDictionary?: string[];
  identifiersPrefix?: string;
  identifierNamesGenerator?: string;
  identifierNamesCache?: Record<string, unknown> | null;
  identifierNamesCachePath?: string;
  inputFileName?: string;
  log?: boolean;
  numbersToExpressions?: boolean;
  optionsPreset?: string;
  renameGlobals?: boolean;
  renameProperties?: boolean;
  renamePropertiesMode?: string;
  reservedNames?: string[];
  reservedStrings?: string[];
  seed?: string | number;
  selfDefending?: boolean;
  simplify?: boolean;
  strictMode?: boolean | null;
  stringArray?: boolean;
  stringArrayCallsTransform?: boolean;
  stringArrayCallsTransformThreshold?: number;
  stringArrayEncoding?: string | string[];
  stringArrayIndexShift?: boolean;
  stringArrayShuffle?: boolean;
  stringArrayIndexesType?: string | string[];
  stringArrayRotate?: boolean;
  stringArrayShuffle?: boolean;
  stringArrayThreshold?: number;
  stringArrayWrappersChainedCalls?: boolean;
  stringArrayWrappersCount?: number;
  stringArrayWrappersParametersMaxCount?: number;
  stringArrayWrappersType?: "variable" | "function";
  transformObjectKeys?: boolean;
  target?: string;
  transformObjectKeys?: boolean;
  unicodeEscapeSequence?: boolean;
  sourceMap?: boolean;
  sourceMapBaseUrl?: string;
  sourceMapFileName?: string;
  sourceMapMode?: string;
  sourceMapSourcesMode?: string;
  splitStrings?: boolean;
  splitStringsChunkLength?: number;
  ignoreImports?: boolean;
}

export interface ResolvedProtectionConfig extends ProtectionOptions {
  endpoint: string;
  apiKey: string;
  apiPassword: string;
  projectName: string;
  input: string;
  output: string;
  preset: PresetName;
  include: string[];
  extensions: string[];
  markupExtensions: string[];
  exclude: string[];
  assetExclude: string[];
  copyAssets: boolean;
  mixedServer: boolean;
  removeSourceMaps: boolean;
  parseHtml: boolean;
  honorConditionalComments: boolean;
  protectMarkedComments: boolean;
  ignoreImports: boolean;
  manifest: string | null;
  maxOutputBytes: number | null;
  maxGrowthRatio: number | null;
  options: Record<string, unknown>;
}

export interface HttpFileItem {
  FileName: string;
  FileCode: string;
}

export interface HttpResult {
  Type: string;
  Items?: HttpFileItem[];
  ErrorCode?: string;
  Message?: string;
  FileName?: string;
  LineNumber?: string;
  ExceptionToString?: string;
}

export interface FileMapping {
  source: string;
  relative: string;
  target: string;
}

export interface ManifestFile {
  fileName: string;
  sourcePath: string;
  outputPath: string;
  sourceBytes: number;
  outputBytes: number;
  sourceSha256: string;
  outputSha256: string;
}

export interface ManifestAsset {
  fileName: string;
  sourcePath: string;
  outputPath: string;
  bytes: number;
  sha256: string;
}

export interface CompetitorLimitation {
  id: string;
  title: string;
  fields: string[];
  message: string;
  recommendation: string;
}

export interface CompetitorCapability {
  id: string;
  capability: string;
  competitorExamples: string[];
  status: "covered" | "partial" | "gap" | string;
  jsoSupport: string;
  evidence: string[];
}

export interface CompetitorGapReportSummary {
  capabilities: number;
  covered: number;
  partial: number;
  gaps: number;
  triggeredLimitations: number;
}

export interface CompetitorGapReport {
  format: "jso-protector-competitor-gap-report";
  version: 1;
  summary: CompetitorGapReportSummary;
  competitors: string[];
  capabilities: CompetitorCapability[];
  limitations: CompetitorLimitation[];
  recommendedPlan: string[];
}

export interface ProtectionManifest {
  format: "jso-protector-manifest";
  version: 1;
  generatedAt: string;
  endpoint: string;
  projectName: string;
  preset: PresetName;
  options: string[];
  processing?: ProtectionProcessingSummary;
  limitations?: CompetitorLimitation[];
  files: ManifestFile[];
  assets: ManifestAsset[];
}

export interface VerifiedManifestEntry {
  kind: "file" | "asset";
  fileName: string;
  path: string;
  ok: boolean;
  reason: "ok" | "missing" | "size-mismatch" | "sha256-mismatch";
  expectedBytes: number;
  expectedSha256: string;
  actualBytes: number | null;
  actualSha256: string | null;
}

export interface ManifestVerificationSummary {
  total: number;
  ok: number;
  missing: number;
  mismatched: number;
}

export interface ManifestVerificationReport {
  format: "jso-protector-manifest-check";
  version: 1;
  ok: boolean;
  manifestPath: string;
  verifyRoot: string | null;
  generatedAt: string;
  projectName: string | null;
  preset: PresetName | null;
  summary: ManifestVerificationSummary;
  files: VerifiedManifestEntry[];
  assets: VerifiedManifestEntry[];
}

export interface ProtectionTransformSummary {
  fileName: string;
  type: string;
  apiItems: number;
  preservedParts: number;
}

export interface ProtectionProcessingSummary {
  apiItems: number;
  transformedFiles: ProtectionTransformSummary[];
}

export interface ProtectionItems {
  items: HttpFileItem[];
  transforms: Map<string, unknown>;
}

export interface ProtectionPlanSummary {
  endpoint: string;
  projectName: string;
  preset: PresetName;
  input: string;
  output: string;
  files: string[];
  assets: string[];
  options: string[];
  processing?: ProtectionProcessingSummary;
}

export interface ProtectionPlan {
  config: ResolvedProtectionConfig;
  files: FileMapping[];
  assets: FileMapping[];
  protection: ProtectionItems;
  summary: ProtectionPlanSummary;
}

export interface ProtectionRunResult extends ProtectionPlanSummary {
  type: string;
  written: string[];
  copied: string[];
  manifestPath: string | null;
  manifest: ProtectionManifest;
  result: HttpResult;
}

export interface ObfuscationResult {
  code: string;
  fileName: string;
  result: HttpResult;
  getObfuscatedCode(): string;
  toString(): string;
  getSourceMap(): null;
  getIdentifierNamesCache(): null;
}

export interface SizeBudgetFailure {
  fileName: string;
  type: "max-output-bytes" | "max-growth-ratio";
  actual: number;
  limit: number;
}

export interface DoctorCheck {
  name: string;
  ok: boolean;
  message: string;
}

export interface DoctorReport {
  ok: boolean;
  endpoint: string;
  projectName: string;
  preset: PresetName;
  input: string;
  output: string;
  files: string[];
  assets: string[];
  limitations: CompetitorLimitation[];
  checks: DoctorCheck[];
}

export interface ValidationCheck {
  name: string;
  level: "ok" | "warning" | "error";
  ok: boolean;
  message: string;
}

export interface ValidationReport {
  ok: boolean;
  strict: boolean;
  warnings: number;
  endpoint: string | null;
  projectName: string | null;
  preset: PresetName | null;
  input: string | null;
  output: string | null;
  limitations: CompetitorLimitation[];
  checks: ValidationCheck[];
}

export interface ReleasePlanReport {
  ok: boolean;
  input: string;
  output: string;
  files: string[];
  assets: string[];
  options: string[];
  processing: ProtectionProcessingSummary;
  manifest: string | null;
  maxOutputBytes: number | null;
  maxGrowthRatio: number | null;
  error: string | null;
}

export interface ReleaseCheckReport {
  format: "jso-protector-release-check";
  version: 1;
  ok: boolean;
  endpoint: string | null;
  projectName: string | null;
  preset: PresetName | null;
  validation: ValidationReport;
  plan: ReleasePlanReport | { ok: false; error: string };
  doctor: DoctorReport | null;
  checkApi: boolean;
}

export interface MigrationMappedOption {
  from: string;
  to: string;
  note?: string;
}

export interface MigrationMapEntry {
  source: string;
  target: string[];
  confidence: "direct" | "approximate";
  note: string;
}

export interface MigrationReviewOption {
  option: string;
  note: string;
}

export interface MigrationMap {
  summary: MigrationMapSummary;
  mappings: MigrationMapEntry[];
  review: MigrationReviewOption[];
}

export interface MigrationMapSummary {
  mapped: number;
  direct: number;
  approximate: number;
  reviewOnly: number;
  totalKnown: number;
}

export interface MigrationReport {
  format: "jso-protector-migration";
  version: 1;
  source: string;
  summary: MigrationReportSummary;
  config: ProtectionOptions;
  mapped: MigrationMappedOption[];
  review: MigrationReviewOption[];
  unmapped: string[];
  nextCommands: MigrationNextCommand[];
  notes: string[];
  reviewReference: MigrationReviewOption[];
}

export interface MigrationNextCommand {
  label: "validate" | "preview" | "doctor" | "release-check" | "competitor-gap" | "protect";
  command: string;
}

export interface MigrationReportSummary {
  sourceOptions: number;
  mappedOptions: number;
  direct: number;
  approximate: number;
  reviewOnly: number;
  unmapped: number;
  automaticCoverage: number;
}

export interface PresetReference {
  name: PresetName;
  options: Record<string, unknown>;
}

export interface OptionReference {
  name: string;
  type: string;
  category: string;
  description: string;
  values?: string[];
}

export interface RedactedProtectionConfig {
  endpoint: string;
  mode: string | null;
  apiKey: "[set]" | "[missing]";
  apiPassword: "[set]" | "[missing]";
  projectName: string;
  preset: PresetName;
  input: string;
  output: string;
  include: string[];
  extensions: string[];
  markupExtensions: string[];
  exclude: string[];
  assetExclude: string[];
  copyAssets: boolean;
  mixedServer: boolean;
  removeSourceMaps: boolean;
  parseHtml: boolean;
  honorConditionalComments: boolean;
  protectMarkedComments: boolean;
  ignoreImports: boolean;
  manifest: string | null;
  maxOutputBytes: number | null;
  maxGrowthRatio: number | null;
  options: Record<string, unknown>;
}

export interface PackageMetadata {
  name: string;
  version: string;
  description: string;
  homepage: string;
  endpoint: string;
}

export interface CompatibilityExplanation {
  option: string;
  status: "mapped" | "review-only" | "unknown" | string;
  target: string[];
  confidence: "direct" | "approximate" | "review" | "unknown" | string;
  note: string;
}

export interface ParsedCliArgs {
  config: string | null;
  mode: string | null;
  input: string | null;
  output: string | null;
  stdin: boolean;
  stdout: boolean;
  fileName: string;
  preset: PresetName | null;
  webPreset: string | null;
  migrateJavascriptObfuscator: string | null;
  migrateJsConfuser: string | null;
  listMigrationMap: boolean;
  listJsConfuserMigrationMap: boolean;
  competitorGapReport: boolean;
  explainCompat: string | null;
  explainJsConfuserCompat: string | null;
  localOnly: boolean;
  options: string[];
  reservedNames: string[];
  include: string[];
  exclude: string[];
  assetExclude: string[];
  parseHtml: boolean | null;
  honorConditionalComments: boolean;
  protectMarkedComments: boolean;
  keepHeaderComment: boolean | null;
  protectObjectDeclaration: boolean | null;
  moveNestedFunction: boolean | null;
  formattedOutput: boolean | null;
  keepIndent: boolean | null;
  lineNumbers: boolean | null;
  manifest: string | null;
  maxOutputBytes: number | null;
  maxGrowthRatio: number | null;
  endpoint: string | null;
  apiKey: string | null;
  apiPassword: string | null;
  doctor: boolean;
  checkApi: boolean;
  releaseCheck: boolean;
  strict: boolean;
  validateConfig: boolean;
  printConfig: boolean;
  listPresets: boolean;
  listOptions: boolean;
  copyAssets: boolean;
  dryRun: boolean;
  json: boolean;
  init: boolean;
  initTemplate: InitTemplateName;
  version: boolean;
  help: boolean;
  compatibilityWarnings: string[];
}

export interface ExampleConfigInitOptions {
  template?: InitTemplateName | "default" | "web" | "browser" | "html" | "node" | "electron" | "desktop" | "next" | "nextjs" | "vite" | "webpack" | "rspack" | "turbopack" | "react-native" | "reactnative" | "metro" | "expo";
  input?: string | null;
  output?: string | null;
  preset?: PresetName | null;
  include?: string[];
  exclude?: string[];
  assetExclude?: string[];
  parseHtml?: ParsedCliArgs["parseHtml"];
  honorConditionalComments?: ParsedCliArgs["honorConditionalComments"] | null;
  protectMarkedComments?: ParsedCliArgs["protectMarkedComments"] | null;
  ignoreImports?: ProtectionOptions["ignoreImports"] | null;
  manifest?: string | null;
  maxOutputBytes?: number | null;
  maxGrowthRatio?: number | null;
  noCopyAssets?: boolean;
  reservedNames?: string[];
  options?: string[];
}

export const DEFAULT_ENDPOINT: string;
export const OPTION_REFERENCE: OptionReference[];
export const PRESET_OPTIONS: Record<PresetName, Record<string, unknown>>;

export function createProtectionConfig(options?: ProtectionOptions): ResolvedProtectionConfig;
export function ensureProtectionConfig(options?: ProtectionOptions | ResolvedProtectionConfig): ResolvedProtectionConfig;
export function obfuscate(code: string, options?: ProtectionOptions | ResolvedProtectionConfig, fileName?: string): Promise<ObfuscationResult>;
export function obfuscateCode(code: string, options?: ProtectionOptions | ResolvedProtectionConfig, fileName?: string): Promise<ObfuscationResult>;
export function obfuscateDirectory(options?: ProtectionOptions | ResolvedProtectionConfig): Promise<ProtectionRunResult>;
export function obfuscateFile(options?: ProtectionOptions | ResolvedProtectionConfig, sourcePath?: string, outputPath?: string): Promise<ProtectionRunResult>;
export function obfuscateFiles(options?: ProtectionOptions | ResolvedProtectionConfig): Promise<ProtectionRunResult>;
export function obfuscateMultiple(sourceCodesObject: Record<string, string>, options?: ProtectionOptions | ResolvedProtectionConfig): Promise<Record<string, ObfuscationResult>>;
export function getOptionsByPreset(optionsPreset?: PresetName): Record<string, unknown>;
export function getPackageMetadata(): PackageMetadata;
export function protectCode(options: ProtectionOptions | ResolvedProtectionConfig, code: string, fileName?: string): Promise<string>;
export function protectCodeDetailed(options: ProtectionOptions | ResolvedProtectionConfig, code: string, fileName?: string): Promise<{ code: string; result: HttpResult; protection: ProtectionItems; processing: ProtectionProcessingSummary }>;
export function protectDirectory(options?: ProtectionOptions | ResolvedProtectionConfig): Promise<ProtectionRunResult>;
export function protectFile(options?: ProtectionOptions | ResolvedProtectionConfig, sourcePath?: string, outputPath?: string): Promise<ProtectionRunResult>;
export function protectFiles(options?: ProtectionOptions | ResolvedProtectionConfig): Promise<ProtectionRunResult>;
export function planProtection(options?: ProtectionOptions | ResolvedProtectionConfig): ProtectionPlan;
export function protectItems(options: ProtectionOptions | ResolvedProtectionConfig, items: HttpFileItem[]): Promise<HttpResult>;
export function translateJsConfuserOptions(sourceOptions?: JsConfuserCompatibilityOptions, overrides?: ProtectionOptions): ProtectionOptions;
export function translateJavascriptObfuscatorOptions(sourceOptions?: JavascriptObfuscatorCompatibilityOptions, overrides?: ProtectionOptions): ProtectionOptions;

export function buildRequest(config: ResolvedProtectionConfig, files: FileMapping[]): Record<string, unknown>;
export function buildRequestFromItems(config: ResolvedProtectionConfig, items: HttpFileItem[]): Record<string, unknown>;
export function buildProtectionItems(config: ResolvedProtectionConfig, files: FileMapping[]): ProtectionItems;
export function buildProtectionItemsFromInputItems(config: ResolvedProtectionConfig, inputItems: HttpFileItem[]): ProtectionItems;
export function describeProtectionTransforms(protection: ProtectionItems): ProtectionProcessingSummary;
export function addProtectionSummary<T extends Record<string, unknown>>(summary: T, protection: ProtectionItems): T & { processing: ProtectionProcessingSummary };
export function buildCodeProtectionPlan(config: ResolvedProtectionConfig, fileName: string, code: string): { items: HttpFileItem[]; transform: unknown };
export function buildCompetitorGapReport(config?: Record<string, unknown>, args?: Record<string, unknown>): CompetitorGapReport;
export function buildCompetitorGapPlan(capabilities: CompetitorCapability[], limitations: CompetitorLimitation[]): string[];
export function buildHtmlProtectionPlan(config: ResolvedProtectionConfig, fileName: string, html: string): { items: HttpFileItem[]; transform: unknown };
export function buildProtectionManifest(config: ResolvedProtectionConfig, files: FileMapping[], assets: FileMapping[], result: HttpResult, transforms?: Map<string, unknown>): ProtectionManifest;
export function buildItemsManifest(config: ResolvedProtectionConfig, inputItems: Array<HttpFileItem & { SourcePath?: string; OutputPath?: string }>, result: HttpResult, outputPathForItem?: (fileName: string) => string, transforms?: Map<string, unknown>): ProtectionManifest;
export function buildMigrationMapSummary(mappings: MigrationMapEntry[], review: MigrationReviewOption[]): MigrationMapSummary;
export function buildMigrationNextCommands(args?: { output?: string }): MigrationNextCommand[];
export function buildMigrationReportSummary(sourceConfig: Record<string, unknown>, mapped: MigrationMappedOption[], review: MigrationReviewOption[], unmapped: string[]): MigrationReportSummary;
export function buildReleasePlan(config: ResolvedProtectionConfig): ReleasePlanReport;
export function buildStdinManifest(config: ResolvedProtectionConfig, fileName: string, sourceCode: string, outputCode: string, outputPath: string, processing?: ProtectionProcessingSummary): ProtectionManifest;
export function assertSizeBudgets(manifest: ProtectionManifest, budgets?: { maxOutputBytes?: number; maxGrowthRatio?: number }): SizeBudgetFailure[];
export function checkSizeBudgets(manifest: ProtectionManifest, budgets?: { maxOutputBytes?: number; maxGrowthRatio?: number }): SizeBudgetFailure[];
export function collectAssets(inputPath: string, outputPath: string, protectedFiles: FileMapping[], assetExcludePatterns: string[]): FileMapping[];
export function collectFiles(inputPath: string, outputPath: string, extensions: string[], excludePatterns: string[], includePatterns?: string[], markupExtensions?: string[]): FileMapping[];
export function copyAssets(assets: FileMapping[]): void;
export function createExampleConfig(initOptions?: string | ExampleConfigInitOptions): ProtectionOptions;
export function getRedactedConfig(config: ResolvedProtectionConfig): RedactedProtectionConfig;
export function globLikeMatch(value: string, pattern: string): boolean;
export function hasConditionalMarkers(code: string): boolean;
export function validateConditionalMarkers(fileName: string, code: string): void;
export function findMarkedHtmlScripts(html: string): Array<{ contentStart: number; contentEnd: number; code: string }>;
export function validateMarkedHtmlScripts(fileName: string, html: string): void;
export function hasMarkedHtmlScriptAttributes(html: string): boolean;
export function hasHtmlProtectionMarkers(filePath: string): boolean;
export function formatSourceLocation(source: string, index: number): string;
export function splitConditionalCode(code: string): Array<{ enabled: boolean; code: string }>;
export function composeProtectionOutput(transform: unknown, byName: Map<string, HttpFileItem>): string | null;
export function composeProtectionItemOutput(fileName: string, result: HttpResult, transforms?: Map<string, unknown>, config?: ResolvedProtectionConfig | ProtectionOptions | null): string;
export function stripSourceMapComments(code: string): string;
export function finalizeProtectedCode(code: string, config?: ResolvedProtectionConfig | ProtectionOptions | null): string;
export function isExcluded(relativePath: string, patterns: string[]): boolean;
export function isIncluded(relativePath: string, patterns: string[]): boolean;
export function listJavascriptObfuscatorMigrationMap(): MigrationMap;
export function listJsConfuserMigrationMap(): MigrationMap;
export function explainCompatibilityOption(option: string): CompatibilityExplanation;
export function explainJsConfuserCompatibilityOption(option: string): CompatibilityExplanation;
export function listOptions(): OptionReference[];
export function listPresets(): PresetReference[];
export function mergeConfig(config: ProtectionOptions & { __configDir?: string }, args?: Partial<ProtectionOptions>): ResolvedProtectionConfig;
export function migrateJsConfuserConfig(sourcePath: string, args?: Partial<ProtectionOptions>): MigrationReport;
export function migrateJavascriptObfuscatorConfig(sourcePath: string, args?: Partial<ProtectionOptions>): MigrationReport;
export function normalizeDomainLockList(value?: string | string[]): string[];
export function normalizeExtensions(extensions: string[]): string[];
export function parseArgs(argv: string[]): ParsedCliArgs;
export function parseOptionOverrides(values: string[]): Record<string, string | number | boolean | null>;
export function parseOptionValue(value: string): string | number | boolean | null;
export function parsePositiveNumber(value: string, option: string): number;
export function presetFromJavascriptObfuscatorPreset(value: string): PresetName;
export function translateJavascriptObfuscatorConfigOptions(source?: ProtectionOptions): ProtectionOptions;
export function postJson(endpoint: string, payload: unknown): Promise<HttpResult>;
export function readConfig(configPath?: string, context?: { mode?: string | null }): ProtectionOptions & { __configDir?: string };
export function readEnv(names: string[]): string;
export function readManifest(manifestPath: string): { manifestPath: string; manifest: ProtectionManifest };
export function readStdin(stream?: unknown): Promise<string>;
export function resolveEnv(value: string): string;
export function runDoctor(config: ResolvedProtectionConfig, args?: { checkApi?: boolean }): Promise<DoctorReport>;
export function runReleaseCheck(config: ProtectionOptions & { __configDir?: string }, args?: Partial<ProtectionOptions> & { checkApi?: boolean; strict?: boolean }): Promise<ReleaseCheckReport>;
export function validateProtectionConfig(config: ProtectionOptions & { __configDir?: string }, args?: Partial<ProtectionOptions> & { strict?: boolean }): ValidationReport;
export function verifyManifestOutputs(manifestPath: string, options?: { verifyRoot?: string }): ManifestVerificationReport;
export function verifyManifestOutputs(manifestInput: { manifestPath: string; manifest: ProtectionManifest }, options?: { verifyRoot?: string }): ManifestVerificationReport;
export function sha256(value: string | Buffer | Uint8Array): string;
export function writeJsConfuserCompatibilityExplanation(option: string, json?: boolean): void;
export function writeJsConfuserMigrationMap(json?: boolean): void;
export function writeCompatibilityExplanation(option: string, json?: boolean): void;
export function writeCompetitorGapReport(report: CompetitorGapReport, json?: boolean): void;
export function writeLocalOnlyGuidance(json?: boolean): void;
export function writeManifestVerificationReport(report: ManifestVerificationReport, json?: boolean): void;
export function writeMigrationMap(json?: boolean): void;
export function writeMigrationReport(report: MigrationReport, args?: { json?: boolean; output?: string }): void;
export function writeReleaseCheckReport(report: ReleaseCheckReport, json?: boolean): void;
export function writeResolvedConfig(config: ResolvedProtectionConfig, json?: boolean): void;
export function writeValidationReport(report: ValidationReport, json?: boolean): void;
export function writeVersion(json?: boolean): void;
export function writeManifest(manifestPath: string, manifest: ProtectionManifest): void;
export function writeResults(files: FileMapping[], result: HttpResult, transforms?: Map<string, unknown>): void;
export function main(argv?: string[]): Promise<void>;

// ----- JSO AI client ----------------------------------------------------
// Wraps the four /v1/ai/* endpoints. Reads JSO_API_KEY / JSO_API_PASSWORD
// from the environment if not passed explicitly.

export interface AiCredentials {
  apiKey?: string;
  apiPassword?: string;
  endpoint?: string;     // default https://www.javascriptobfuscator.com
  timeoutMs?: number;    // default 30000
}

export interface AiEnvelope {
  ok: boolean;
  previewMode?: boolean;
  provider?: string;
  tokensIn?: number;
  tokensOut?: number;
  error?: string;
  message?: string;
}

export interface AiPresetSuggestResult extends AiEnvelope {
  suggestion?: {
    previewMode: boolean;
    source: string;
    config: Record<string, unknown>;
    signals: string[];
  };
}

export interface AiCompatCheckFinding {
  category: string;
  severity: "error" | "warning" | "info";
  line: number;
  column: number;
  snippet?: string;
  message: string;
  suggestedFix: string;
}

export interface AiCompatCheckResult extends AiEnvelope {
  report?: {
    previewMode: boolean;
    source: string;
    summary: { errors: number; warnings: number; infos: number };
    findings: AiCompatCheckFinding[];
  };
}

export interface AiExplainErrorResult extends AiEnvelope {
  explanation?: {
    previewMode: boolean;
    source: string;
    cause: string;
    transform: string;
    confidence: "high" | "medium" | "low";
    explanation: string;
    fix: string;
    docsUrl: string;
  };
}

export interface AiProviderKeyHealth {
  hasKey: boolean;
  provider: "" | "openai" | "claude";
  status: "missing" | "disabled" | "test-needed" | "failed" | "test-due" | "rotation-review-due" | "ready";
  label: string;
  testDue: boolean;
  rotationDue: boolean;
  lastTestStatus: string;
  lastTestUtc: string | null;
  nextTestDueUtc: string | null;
  rotationDueUtc: string | null;
  recommendedAction: string;
}

export interface AiUsageResult extends AiEnvelope {
  tier?: "FreeTrial" | "Basic" | "Corporate" | "Enterprise";
  billingMonth?: string;
  actionsUsed?: number;
  actionsCap?: number;
  actionsRemaining?: number;
  tokensUsed?: number;
  tokensCap?: number;
  tokensRemaining?: number;
  approxCostCents?: number;
  costCapCents?: number;
  costRemainingCents?: number;
  providerKey?: AiProviderKeyHealth;
  quotaRejections?: number;
  asOfUtc?: string;
}

export const ai: {
  presetSuggest(opts: AiCredentials & { description: string }): Promise<AiPresetSuggestResult>;
  compatCheck (opts: AiCredentials & { source: string; framework?: string }): Promise<AiCompatCheckResult>;
  explainError(opts: AiCredentials & { error: string; config?: string }): Promise<AiExplainErrorResult>;
  usage       (opts?: AiCredentials): Promise<AiUsageResult>;
};
