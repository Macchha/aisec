// Stand-in for the project's database handle, so `index.ts` resolves the `db` it
// concatenates SQL into (MCP014). Nothing here is executed; the fixture is source
// the scanner reads, not a server anyone runs.
export const db = {
  async query(_sql: string): Promise<unknown[]> {
    return [];
  },
};
