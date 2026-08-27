export interface DataExfiltrationPolicyInput { id?: string; version?: string; mode?: "monitor" | "block"; pageOrigin?: string; allowedOrigins?: string[]; protectedSelectors?: string[]; protectedFieldNames?: string[]; allowSameOrigin?: boolean; }
export interface DataExfiltrationEvent { seq: number; reason: string; transport: string; method: string | null; destinationOrigin: string | null; protectedFieldNames: readonly string[]; protectedFieldCount: number; protectedValueCount: number; protectedForm: boolean; blocked: boolean; observedAt: string; }
export declare const SCHEMA_VERSION: 1;
export declare const DEFAULT_SELECTORS: readonly string[];
export declare function createPolicy(input?: DataExfiltrationPolicyInput): object;
export declare function createGuard(input?: DataExfiltrationPolicyInput | object): { policy: object; inspect(row: object): object; events(): DataExfiltrationEvent[]; reset(): void; snapshot(): object; detach?: () => void; };
export declare function attach(win: Window, input?: DataExfiltrationPolicyInput): ReturnType<typeof createGuard>;
