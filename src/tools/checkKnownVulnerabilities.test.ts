
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkKnownVulnerabilities, CheckKnownVulnerabilitiesOutput, Vulnerability } from './checkKnownVulnerabilities.js';
import * as osv from '../core/osv.js';
import * as analyzer from '../core/analyzer.js';
import * as validatePath from '../lib/validate-path.js';
import { OsvVulnerability } from '../core/osv.js';

vi.mock('../core/osv.js');
vi.mock('../core/analyzer.js');
vi.mock('../lib/validate-path.js');

describe('checkKnownVulnerabilities', () => {
  const projectPath = '/fake/project';

  beforeEach(() => {
    vi.resetAllMocks();

    vi.mocked(validatePath.validateProjectPath).mockResolvedValue(projectPath);

    vi.mocked(analyzer.readPackageJson).mockResolvedValue({
      dependencies: {
        'react': '18.2.0',
      },
    });
  });

  it('should return vulnerability information for a given project', async () => {
    const mockOsvVulnerability: OsvVulnerability = {
      id: 'CVE-2023-1234',
      summary: 'A critical vulnerability',
      details: 'Details about the vulnerability',
      affected: [{
        package: { name: 'react', ecosystem: 'npm' },
        versions: ['18.2.0']
      }],
      references: [],
      severity: [{ type: 'CVSS_V3', score: '9.8' }]
    };

    const mockOsvResponse = new Map<string, OsvVulnerability[]>([[
      'react',
      [mockOsvVulnerability]
    ]]);
    vi.mocked(osv.queryOsv).mockResolvedValue(mockOsvResponse);

    const result: CheckKnownVulnerabilitiesOutput = await checkKnownVulnerabilities({ projectPath });

    expect(osv.queryOsv).toHaveBeenCalledWith([{ name: 'react', version: '18.2.0' }]);
    expect(result.summary.total).toBe(1);
    expect(result.summary.critical).toBe(1);
    expect(result.vulnerabilities.critical).toHaveLength(1);
    const vulnerability: Vulnerability = result.vulnerabilities.critical[0];
    expect(vulnerability.packageName).toBe('react');
    expect(vulnerability.vulnerability.id).toBe('CVE-2023-1234');
  });

  it('should handle packages with no vulnerabilities', async () => {
    const mockOsvResponse = new Map<string, OsvVulnerability[]>([[
      'react',
      []
    ]]);
    vi.mocked(osv.queryOsv).mockResolvedValue(mockOsvResponse);

    const result = await checkKnownVulnerabilities({ projectPath });

    expect(result.summary.total).toBe(0);
    expect(result.summary.critical).toBe(0);
    expect(result.summary.high).toBe(0);
  });

  it('should handle API errors gracefully', async () => {
    vi.mocked(osv.queryOsv).mockRejectedValue(new Error('API Error'));

    const result = await checkKnownVulnerabilities({ projectPath });

    expect(result.summary.total).toBe(0);
  });
});
