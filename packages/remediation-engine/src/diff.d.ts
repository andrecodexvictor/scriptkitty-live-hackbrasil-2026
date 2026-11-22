declare module 'diff' {
  export interface Hunk {
    oldStart: number;
    oldLines: number;
    newStart: number;
    newLines: number;
    lines: string[];
    linedelimiters: string[];
  }

  export interface StructuredPatch {
    oldFileName: string;
    newFileName: string;
    oldHeader: string;
    newHeader: string;
    hunks: Hunk[];
  }

  export interface PatchOptions {
    context?: number;
    ignoreWhitespace?: boolean;
  }

  export interface ApplyPatchOptions {
    fuzzFactor?: number;
    compareLine?: (lineNumber: number, line: string, operation: string, patchContent: string) => boolean;
  }

  export function structuredPatch(
    oldFileName: string,
    newFileName: string,
    oldStr: string,
    newStr: string,
    oldHeader?: string,
    newHeader?: string,
    options?: PatchOptions
  ): StructuredPatch;

  export function applyPatch(
    source: string,
    patch: string | StructuredPatch | StructuredPatch[],
    options?: ApplyPatchOptions
  ): string | false;

  export function parsePatch(
    diffStr: string,
    options?: { strict?: boolean }
  ): StructuredPatch[];
}
