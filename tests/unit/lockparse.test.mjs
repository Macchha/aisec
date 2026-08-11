import { describe, it, expect } from 'vitest';
import { parseLockfile, UnsupportedLockfile, MAX_DEPS, LOCKFILE_NAMES } from '../../plugin/scripts/lib/lockparse.mjs';

describe('package-lock.json', () => {
  it('parses v3 packages keyed by install path', () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/a/node_modules/lodash': { version: '3.0.0' },
      },
    });
    const { deps } = parseLockfile(text, 'package-lock.json');
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '3.0.0' });
    expect(deps.find(d => d.name === 'root')).toBeUndefined();
  });

  it('parses v1 nested dependencies', () => {
    const text = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.21', dependencies: { minimist: { version: '1.2.0' } } } },
    });
    const { deps } = parseLockfile(text, 'package-lock.json');
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'minimist', version: '1.2.0' });
  });

  it('deduplicates identical name@version pairs', () => {
    const text = JSON.stringify({
      packages: { 'node_modules/a': { version: '1.0.0' }, 'node_modules/b/node_modules/a': { version: '1.0.0' } },
    });
    expect(parseLockfile(text, 'package-lock.json').deps).toHaveLength(1);
  });

  it('rejects invalid JSON', () => {
    expect(() => parseLockfile('{nope', 'package-lock.json')).toThrow(/valid JSON/);
  });
});

describe('yarn.lock (classic)', () => {
  it('extracts names and versions', () => {
    const text = [
      '# yarn lockfile v1', '',
      '"@scope/pkg@^1.0.0":', '  version "1.2.3"', '',
      'lodash@^4.0.0:', '  version "4.17.21"', '',
    ].join('\n');
    const { deps } = parseLockfile(text, 'yarn.lock');
    expect(deps).toContainEqual({ ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' });
  });
});

describe('pnpm-lock.yaml', () => {
  it('extracts packages in both v6 and v9 key styles', () => {
    const text = [
      'lockfileVersion: 9.0', 'packages:', '',
      '  /lodash@4.17.21:', '    resolution: {integrity: sha512-x}', '',
      '  @scope/pkg@1.2.3:', '    resolution: {integrity: sha512-y}', '',
    ].join('\n');
    const { deps } = parseLockfile(text, 'pnpm-lock.yaml');
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3' });
  });
});

describe('python formats', () => {
  it('parses pinned requirements.txt lines and ignores the rest', () => {
    const text = ['requests==2.31.0', '# comment', '-r other.txt', 'flask>=2.0', 'urllib3==2.0.7  # inline'].join('\n');
    const { deps } = parseLockfile(text, 'requirements.txt');
    expect(deps).toEqual([
      { ecosystem: 'PyPI', name: 'requests', version: '2.31.0' },
      { ecosystem: 'PyPI', name: 'urllib3', version: '2.0.7' },
    ]);
  });

  it('parses uv.lock TOML package blocks', () => {
    const text = ['[[package]]', 'name = "requests"', 'version = "2.31.0"', '',
                  '[[package]]', 'name = "urllib3"', 'version = "2.0.7"'].join('\n');
    const { deps } = parseLockfile(text, 'uv.lock');
    expect(deps).toHaveLength(2);
    expect(deps[0]).toEqual({ ecosystem: 'PyPI', name: 'requests', version: '2.31.0' });
  });

  it('parses poetry.lock the same way', () => {
    const text = ['[[package]]', 'name = "flask"', 'version = "3.0.0"', 'optional = false'].join('\n');
    expect(parseLockfile(text, 'poetry.lock').deps)
      .toEqual([{ ecosystem: 'PyPI', name: 'flask', version: '3.0.0' }]);
  });
});

describe('limits and unsupported formats', () => {
  it('throws UnsupportedLockfile for an unknown filename', () => {
    expect(() => parseLockfile('x', 'Gemfile.lock')).toThrow(UnsupportedLockfile);
  });

  it('caps the dependency list at MAX_DEPS', () => {
    const packages = {};
    for (let i = 0; i < MAX_DEPS + 50; i++) packages[`node_modules/p${i}`] = { version: '1.0.0' };
    expect(parseLockfile(JSON.stringify({ packages }), 'package-lock.json').deps).toHaveLength(MAX_DEPS);
  });

  it('reports truncation so the caller can record it as unscanned', () => {
    const packages = {};
    for (let i = 0; i < MAX_DEPS + 600; i++) packages[`node_modules/p${i}`] = { version: '1.0.0' };
    const r = parseLockfile(JSON.stringify({ packages }), 'package-lock.json');
    expect(r.truncated).toBe(true);
    expect(r.total).toBe(MAX_DEPS + 600);
  });

  it('reports truncated false and an accurate total when under the cap', () => {
    const r = parseLockfile(JSON.stringify({
      packages: { 'node_modules/a': { version: '1.0.0' }, 'node_modules/b': { version: '2.0.0' } },
    }), 'package-lock.json');
    expect(r.truncated).toBe(false);
    expect(r.total).toBe(2);
  });

  it('labels every supported format', () => {
    const fmt = (name, text = '{}') => parseLockfile(text, name).format;
    expect(fmt('package-lock.json')).toBe('npm package-lock');
    expect(fmt('yarn.lock', '')).toBe('yarn classic lockfile');
    expect(fmt('pnpm-lock.yaml', '')).toBe('pnpm lockfile');
    expect(fmt('requirements.txt', '')).toBe('pip requirements');
    expect(fmt('uv.lock', '')).toBe('uv lockfile');
    expect(fmt('poetry.lock', '')).toBe('poetry lockfile');
  });

  it('exports the filenames the scanner looks for', () => {
    expect(LOCKFILE_NAMES).toContain('package-lock.json');
    expect(LOCKFILE_NAMES).toContain('pnpm-lock.yaml');
    expect(LOCKFILE_NAMES).toHaveLength(6);
  });
});

// Real pnpm 9/10 single-quotes any key beginning with '@', because YAML reserves it.
// The plan's original miniature used an unquoted scoped key, a shape pnpm never emits.
describe('pnpm real-world key shapes', () => {
  it('parses single-quoted scoped keys (pnpm v9/v10)', () => {
    const text = [
      "lockfileVersion: '9.0'", 'packages:', '',
      "  '@babel/traverse@7.23.0':", '    resolution: {integrity: sha512-x}', '',
      "  '@modelcontextprotocol/sdk@1.0.4':", '    resolution: {integrity: sha512-y}', '',
      '  lodash@4.17.21:', '    resolution: {integrity: sha512-z}', '',
    ].join('\n');
    const { deps } = parseLockfile(text, 'pnpm-lock.yaml');
    expect(deps).toContainEqual({ ecosystem: 'npm', name: '@babel/traverse', version: '7.23.0' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: '@modelcontextprotocol/sdk', version: '1.0.4' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' });
    expect(deps).toHaveLength(3);
  });

  it('emits no rows named after a stray quote', () => {
    const text = ["  '@babel/traverse@7.23.0':", '    resolution: {integrity: sha512-x}'].join('\n');
    const { deps } = parseLockfile(text, 'pnpm-lock.yaml');
    expect(deps.some(d => d.name === "'" || d.name.includes("'"))).toBe(false);
  });

  it('ignores quoted dependency sub-entries that carry no version in the key', () => {
    const text = [
      'packages:', '', '  /lodash@4.17.21:', '    resolution: {integrity: sha512-z}',
      '    dependencies:', "      '@babel/core': 7.24.0", '      minimist: 1.2.6',
    ].join('\n');
    const { deps } = parseLockfile(text, 'pnpm-lock.yaml');
    expect(deps).toEqual([{ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }]);
  });

  it('takes the version, not the peer-dependency suffix', () => {
    const text = '  /@babel/helper-x@7.1.0(@babel/core@7.24.0):\n    resolution: {integrity: sha512-q}';
    expect(parseLockfile(text, 'pnpm-lock.yaml').deps)
      .toEqual([{ ecosystem: 'npm', name: '@babel/helper-x', version: '7.1.0' }]);
  });
});

// npm records the real package for an alias in `info.name`; the install path holds the alias.
describe('aliased and first-party packages', () => {
  it('resolves an npm alias to the real package name', () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 'root' }, 'node_modules/my-alias': { name: 'minimist', version: '1.2.0' } },
    });
    expect(parseLockfile(text, 'package-lock.json').deps)
      .toEqual([{ ecosystem: 'npm', name: 'minimist', version: '1.2.0' }]);
  });

  it('resolves a yarn npm: alias to the real package name', () => {
    const text = ['"my-alias@npm:minimist@^1.2.0":', '  version "1.2.0"', ''].join('\n');
    expect(parseLockfile(text, 'yarn.lock').deps)
      .toEqual([{ ecosystem: 'npm', name: 'minimist', version: '1.2.0' }]);
  });

  it('does not emit workspace directories as third-party packages', () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root' },
        'packages/inner': { name: 'inner-pkg', version: '2.5.0' },
        'node_modules/lodash': { version: '4.17.21' },
      },
    });
    expect(parseLockfile(text, 'package-lock.json').deps)
      .toEqual([{ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }]);
  });

  it('skips versionless link entries', () => {
    const text = JSON.stringify({
      packages: { 'node_modules/linked': { link: true }, 'node_modules/real': { version: '1.0.0' } },
    });
    expect(parseLockfile(text, 'package-lock.json').deps)
      .toEqual([{ ecosystem: 'npm', name: 'real', version: '1.0.0' }]);
  });
});

describe('requirements.txt real-world lines', () => {
  it('keeps the base name when extras are present', () => {
    const { deps } = parseLockfile('uvicorn[standard]==0.27.0', 'requirements.txt');
    expect(deps).toEqual([{ ecosystem: 'PyPI', name: 'uvicorn', version: '0.27.0' }]);
  });

  it('tolerates PEP 508 whitespace around extras and the operator', () => {
    const { deps } = parseLockfile('requests [security] == 2.31.0', 'requirements.txt');
    expect(deps).toEqual([{ ecosystem: 'PyPI', name: 'requests', version: '2.31.0' }]);
  });

  it('parses PEP 440 arbitrary equality', () => {
    const { deps } = parseLockfile('Django===4.0.0', 'requirements.txt');
    expect(deps).toEqual([{ ecosystem: 'PyPI', name: 'Django', version: '4.0.0' }]);
  });
});

describe('dedup key includes the ecosystem', () => {
  it('does not collapse a PyPI and an npm package of the same name and version', () => {
    const req = parseLockfile('shared==1.0.0', 'requirements.txt').deps;
    const npm = parseLockfile(JSON.stringify({ packages: { 'node_modules/shared': { version: '1.0.0' } } }),
      'package-lock.json').deps;
    expect(req[0].ecosystem).toBe('PyPI');
    expect(npm[0].ecosystem).toBe('npm');
  });
});
