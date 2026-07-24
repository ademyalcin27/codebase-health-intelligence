
import { vi } from 'vitest';

vi.doMock('fs/promises', () => ({
  readFile: vi.fn(),
}));

vi.doMock('../lib/validate-path.js', () => ({
  validateProjectPath: vi.fn(() => Promise.resolve()),
}));

vi.doMock('../core/osv.js', () => ({
    queryOsv: vi.fn(),
}));
