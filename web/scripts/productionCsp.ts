import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const dynamicCodeGenerationMarkers = [
  { label: 'eval()', pattern: /(?:^|[^\w$])eval\s*\(/u },
  {
    label: 'Function constructor',
    pattern: /(?:^|[^\w$])new\s+Function\s*\(/u,
  },
  {
    label: 'Function constructor call',
    pattern: /(?:^|[^\w$])Function\s*\(/u,
  },
  {
    label: 'string-form timer',
    pattern:
      /(?:^|[^\w$.])(?:(?:(?:globalThis|window|self)\s*(?:\.\s*(?:setTimeout|setInterval)|\[\s*(?:"|')(?:setTimeout|setInterval)(?:"|')\s*\]))|(?:setTimeout|setInterval))\s*\(\s*(?:"|'|`)/u,
  },
  {
    label: 'WebAssembly dynamic code generation',
    pattern:
      /(?:^|[^\w$])WebAssembly\s*(?:\.\s*(?:compile|compileStreaming|instantiate|instantiateStreaming|Module)\s*\(|\[\s*(?:"|')(?:compile|compileStreaming|instantiate|instantiateStreaming|Module)(?:"|')\s*\]\s*\()/u,
  },
] as const;

function productionJavaScriptChunks(root: string): readonly string[] {
  const chunks: string[] = [];

  function visit(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if (entry.isFile() && extname(entry.name) === '.js') {
        chunks.push(path);
      }
    }
  }

  visit(root);
  return chunks.sort();
}

export interface ProductionCspScanResult {
  readonly chunks: readonly string[];
}

export function scanProductionJavaScriptChunks(
  outputDirectory = resolve(process.cwd(), 'dist'),
): ProductionCspScanResult {
  const chunks = productionJavaScriptChunks(outputDirectory);
  if (chunks.length === 0) {
    throw new Error('production CSP scan found no JavaScript chunks');
  }

  for (const chunk of chunks) {
    const source = readFileSync(chunk, 'utf8');
    for (const marker of dynamicCodeGenerationMarkers) {
      if (marker.pattern.test(source)) {
        throw new Error(
          `production CSP scan rejected ${relative(outputDirectory, chunk)}: ${marker.label}`,
        );
      }
    }
  }

  return {
    chunks: chunks.map((chunk) => relative(outputDirectory, chunk)),
  };
}
