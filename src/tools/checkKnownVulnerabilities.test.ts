
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkKnownVulnerabilities } from './checkKnownVulnerabilities.js';
import { queryOsv } from '../core/osv.js';
import { promises as fs } from 'fs';

describe('checkKnownVulnerabilities', () => {
  const projectPath = '/fake/project';
  const packageJson = {
    dependencies: {
      'react': '18.2.0',
    },
  };
  const packageLockJson = {
    packages: {
      'node_modules/react': {
        name: 'react',
        version: '18.2.0',
      },
    },
  };

  beforeEach(() => {
    vi.spyOn(fs, 'readFile').mockImplementation((path) => {
      if (path.toString().endsWith('package.json')) {
        return Promise.resolve(JSON.stringify(packageJson));
      }
      if (path.toString().endsWith('package-lock.json')) {
        return Promise.resolve(JSON.stringify(packageLockJson));
      }
      return Promise.reject(new Error(`File not found: ${path}`));
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should return vulnerability information for a given project', async () => {
    const mockOsvResponse = new Map([
        ['react@18.2.0', {
          vulns: [
            {
              id: 'CVE-2023-1234',
              severity: [{ type: 'CVSS_V3', score: '9.8' }],
              affected: [{ ranges: [{ type: 'SEMVER', events: [{}, { fixed: '18.2.1' }] }] }],
            },
          ],
        }],
      ]);
    vi.mocked(queryOsv).mockResolvedValue(mockOsvResponse);

    const vulnerabilities = await checkKnownVulnerabilities({ projectPath });

    expect(queryOsv).toHaveBeenCalledWith([{ name: 'react', version: '18.2.0' }]);
    expect(vulnerabilities.critical).toHaveLength(1);
    expect(vulnerabilities.critical[0]).toEqual({
      package: 'react@18.2.0',
      id: 'CVE-2023-1234',
      severity: 'critical',
      fixedVersion: '18.2.1',
    });
  });

  it('should handle packages with no vulnerabilities', async () => {
    const mockOsvResponse = new Map([
      ['react@18.2.0', { vulns: [] }],
    ]);
    vi.mocked(queryOsv).mockResolvedValue(mockOsvResponse);

    const vulnerabilities = await checkKnownVulnerabilities({ projectPath });

    expect(vulnerabilities.critical).toHaveLength(0);
    expect(vulnerabilities.high).toHaveLength(0);
    expect(vulnerabilities.medium).toHaveLength(0);
    expect(vulnerabilities.low).toHaveLength(0);
  });

  it('should handle API errors gracefully', async () => {
    const mockOsvResponse = new Map([
      ['react@18.2.0', null],
    ]);
    vi.mocked(queryOsv).mockResolvedValue(mockOsvResponse);

    const vulnerabilities = await checkKnownVulnerabilities({ projectPath });

    expect(vulnerabilities.unknown).toHaveLength(1);
    expect(vulnerabilities.unknown[0]).toEqual({
      package: 'react@18.2.0',
    });
  });
});
