declare module 'node:sqlite' {
  export interface StatementRunResult {
    changes: number;
    lastInsertRowid: number | bigint;
  }

  export class StatementSync {
    all(...params: unknown[]): Record<string, any>[];
    get(...params: unknown[]): Record<string, any> | undefined;
    run(...params: unknown[]): StatementRunResult;
  }

  export class DatabaseSync {
    constructor(location: string, options?: { open?: boolean });
    close(): void;
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
  }
}
