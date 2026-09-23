import { performance } from "node:perf_hooks";
const started = performance.now();
await new Promise((resolve) => setTimeout(resolve, 1));
console.log(`Benchmark fixture baseline: ${(performance.now() - started).toFixed(2)}ms`);
console.log("Run Linux fixture benchmarks only after real sandbox validation; no comparative claim is emitted here.");
