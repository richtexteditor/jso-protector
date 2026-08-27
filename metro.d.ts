import type { HttpFileItem, HttpResult, ProtectionOptions } from "./index";

export interface MetroSerializerOptionsLike {
  dev?: boolean;
  platform?: string | null;
  projectRoot?: string;
  [key: string]: unknown;
}

export interface MetroSerializerResultLike {
  code: string | Buffer;
  map?: unknown;
  assets?: readonly unknown[];
  [key: string]: unknown;
}

export type MetroSerializerLike = (
  entryPoint: string,
  preModules: readonly unknown[],
  graph: unknown,
  options: MetroSerializerOptionsLike
) => string | Buffer | MetroSerializerResultLike | Promise<string | Buffer | MetroSerializerResultLike>;

export interface JsoProtectorMetroOptions extends ProtectionOptions {
  fileName?: string;
  removeSourceMaps?: boolean;
  serializer?: MetroSerializerLike;
  protectItems?: (config: ProtectionOptions, items: HttpFileItem[]) => Promise<HttpResult>;
}

export interface MetroConfigLike {
  serializer?: {
    customSerializer?: MetroSerializerLike;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

declare function createMetroSerializer(options?: JsoProtectorMetroOptions): MetroSerializerLike;
declare function withJsoProtectorMetro(baseConfig?: MetroConfigLike, options?: JsoProtectorMetroOptions): MetroConfigLike;

export { createMetroSerializer, withJsoProtectorMetro };
export default createMetroSerializer;
