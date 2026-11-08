// S12 spike: the --import variant (ESM preload) of loader.cjs. THROWAWAY.
import { createRequire } from 'module';
createRequire(import.meta.url)('./loader.cjs');
