// Ported from vulnrable/src/lib/mcp-known.ts (TS types stripped).
// Cap = 'fs' | 'data' | 'fetch' | 'exec' | 'msg' | 'other'
// KnownServer = { name, ecosystem: 'npm' | 'PyPI', caps: Cap[] }

// Seed list: official modelcontextprotocol servers + popular community servers.
// Doubles as typosquat reference and getStaticPaths seed for /mcp/[slug].
export const KNOWN_SERVERS = [
  { name: '@modelcontextprotocol/server-filesystem', ecosystem: 'npm', caps: ['fs'] },
  { name: '@modelcontextprotocol/server-memory', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-github', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-gitlab', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-google-maps', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@modelcontextprotocol/server-slack', ecosystem: 'npm', caps: ['msg'] },
  { name: '@modelcontextprotocol/server-postgres', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-puppeteer', ecosystem: 'npm', caps: ['fetch', 'exec'] },
  { name: '@modelcontextprotocol/server-brave-search', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@modelcontextprotocol/server-everything', ecosystem: 'npm', caps: ['other'] },
  { name: '@modelcontextprotocol/server-sequential-thinking', ecosystem: 'npm', caps: ['other'] },
  { name: '@modelcontextprotocol/server-gdrive', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-aws-kb-retrieval', ecosystem: 'npm', caps: ['data'] },
  { name: '@modelcontextprotocol/server-everart', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@modelcontextprotocol/server-redis', ecosystem: 'npm', caps: ['data'] },
  { name: 'firecrawl-mcp', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@playwright/mcp', ecosystem: 'npm', caps: ['fetch', 'exec'] },
  { name: '@executeautomation/playwright-mcp-server', ecosystem: 'npm', caps: ['fetch', 'exec'] },
  { name: 'exa-mcp-server', ecosystem: 'npm', caps: ['fetch'] },
  { name: 'tavily-mcp', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@upstash/context7-mcp', ecosystem: 'npm', caps: ['fetch'] },
  { name: '@supabase/mcp-server-supabase', ecosystem: 'npm', caps: ['data'] },
  { name: '@notionhq/notion-mcp-server', ecosystem: 'npm', caps: ['data'] },
  { name: '@stripe/mcp', ecosystem: 'npm', caps: ['data'] },
  { name: '@cloudflare/mcp-server-cloudflare', ecosystem: 'npm', caps: ['data'] },
  { name: '@sentry/mcp-server', ecosystem: 'npm', caps: ['data'] },
  { name: '@browserbasehq/mcp', ecosystem: 'npm', caps: ['fetch', 'exec'] },
  { name: 'mcp-remote', ecosystem: 'npm', caps: ['other'] },
  { name: 'mongodb-mcp-server', ecosystem: 'npm', caps: ['data'] },
  { name: '@elastic/mcp-server-elasticsearch', ecosystem: 'npm', caps: ['data'] },
  { name: '@neondatabase/mcp-server-neon', ecosystem: 'npm', caps: ['data'] },
  { name: 'mcp-server-kubernetes', ecosystem: 'npm', caps: ['exec', 'data'] },
  { name: '@azure/mcp', ecosystem: 'npm', caps: ['data'] },
  { name: '@heroku/mcp-server', ecosystem: 'npm', caps: ['data'] },
  { name: '@wonderwhy-er/desktop-commander', ecosystem: 'npm', caps: ['fs', 'exec'] },
  { name: '@agentdeskai/browser-tools-mcp', ecosystem: 'npm', caps: ['fetch'] },
  { name: 'figma-developer-mcp', ecosystem: 'npm', caps: ['fetch'] },
  { name: 'graphlit-mcp-server', ecosystem: 'npm', caps: ['data'] },
  { name: 'mcp-server-fetch', ecosystem: 'PyPI', caps: ['fetch'] },
  { name: 'mcp-server-git', ecosystem: 'PyPI', caps: ['data'] },
  { name: 'mcp-server-time', ecosystem: 'PyPI', caps: ['other'] },
  { name: 'mcp-server-sqlite', ecosystem: 'PyPI', caps: ['data'] },
  { name: 'mcp-server-sentry', ecosystem: 'PyPI', caps: ['data'] },
];

export function capsOf(s) {
  if (s.pkg) {
    const known = KNOWN_SERVERS.find(k => k.name === s.pkg.name && k.ecosystem === s.pkg.ecosystem);
    if (known) return known.caps;
  }
  const id = `${s.pkg?.name ?? ''} ${s.serverKey} ${s.url ?? ''}`.toLowerCase();
  const caps = [];
  if (/file|fs\b|filesystem|desktop/.test(id)) caps.push('fs');
  if (/fetch|search|browser|scrape|crawl|http|web/.test(id)) caps.push('fetch');
  if (/shell|exec|terminal|command|kubernetes/.test(id)) caps.push('exec');
  if (/slack|mail|discord|telegram|sms/.test(id)) caps.push('msg');
  if (/db|postgres|sql|mongo|redis|memory|drive|github|gitlab|notion|stripe/.test(id)) caps.push('data');
  return caps;
}
