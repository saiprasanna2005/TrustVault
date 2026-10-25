import { defineConfig } from 'vitest/config'
import { loadEnv } from 'vite'

// Loads .env.test (git-ignored) so the security tests can read SUPABASE_* values.
export default defineConfig(({ mode }) => ({
  test: {
    env: loadEnv(mode, process.cwd(), ''),
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
}))
