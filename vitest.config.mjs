import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.test.mjs'],
    // vi.restoreAllMocks() does not undo vi.stubGlobal. Without this, a test that forgets
    // to stub fetch would silently inherit the previous test's stub instead of failing.
    unstubGlobals: true,
  },
});
