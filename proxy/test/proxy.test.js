const request = require('supertest');
const { app, parseTarballUrl } = require('../src/server');
const scanner = require('../src/scanner');
const cache = require('../src/cache');

jest.mock('../src/scanner');

describe('URL Parser', () => {
  it('parses unscoped tarball URLs', () => {
    const res = parseTarballUrl('/express/-/express-4.18.2.tgz');
    expect(res).toEqual({ isTarball: true, name: 'express', version: '4.18.2' });
  });

  it('parses scoped tarball URLs (unencoded)', () => {
    const res = parseTarballUrl('/@babel/core/-/core-7.24.0.tgz');
    expect(res).toEqual({ isTarball: true, name: '@babel/core', version: '7.24.0' });
  });

  it('parses scoped tarball URLs (encoded)', () => {
    const res = parseTarballUrl('/@babel%2fcore/-/core-7.24.0.tgz');
    expect(res).toEqual({ isTarball: true, name: '@babel/core', version: '7.24.0' });
  });

  it('ignores metadata requests', () => {
    expect(parseTarballUrl('/express').isTarball).toBe(false);
    expect(parseTarballUrl('/express/4.18.2').isTarball).toBe(false);
    expect(parseTarballUrl('/-/v1/search?text=express').isTarball).toBe(false);
  });
});

describe('Proxy Server', () => {
  beforeEach(async () => {
    jest.clearAllMocks();
    await cache.setCachedResult('is-number', '7.0.0', undefined);
    await cache.setCachedResult('evil-pkg', '1.0.0', undefined);
  });

  it('passes through metadata requests transparently', async () => {
    // This will actually hit registry.npmjs.org for is-number
    const res = await request(app).get('/is-number');
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('is-number');
    expect(scanner.scanTarball).not.toHaveBeenCalled();
  });

  it('downloads, scans, and forwards clean packages', async () => {
    scanner.scanTarball.mockResolvedValue({ verdict: 'clean', confidence: 0.99, scan_time_ms: 100 });
    
    // We request a real, tiny package
    const res = await request(app).get('/is-number/-/is-number-7.0.0.tgz');
    
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/octet-stream');
    expect(scanner.scanTarball).toHaveBeenCalledTimes(1);
    
    // Check cache
    const cached = await cache.getCachedResult('is-number', '7.0.0');
    expect(cached.verdict).toBe('clean');
  });

  it('returns 403 for malicious packages', async () => {
    scanner.scanTarball.mockResolvedValue({ 
      verdict: 'malicious', 
      confidence: 0.94, 
      evidence: ['CRIT_INSTALL_HOOK_NETWORK'],
      decision_path: 'GNN + Rules'
    });
    
    const res = await request(app).get('/is-odd/-/is-odd-3.0.0.tgz'); // using is-odd as dummy
    
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('BLOCKED by SupplyGuard Agentic Firewall');
    expect(res.body.verdict).toBe('malicious');
    expect(scanner.scanTarball).toHaveBeenCalledTimes(1);
  });

  it('uses cache for subsequent requests', async () => {
    scanner.scanTarball.mockResolvedValue({ verdict: 'clean', confidence: 0.99 });
    
    await request(app).get('/is-array/-/is-array-1.0.1.tgz');
    expect(scanner.scanTarball).toHaveBeenCalledTimes(1);
    
    await request(app).get('/is-array/-/is-array-1.0.1.tgz');
    // Still 1!
    expect(scanner.scanTarball).toHaveBeenCalledTimes(1);
  });

  it('fails open if scanner is unreachable', async () => {
    scanner.scanTarball.mockResolvedValue({ verdict: 'error', error: 'Scanner unreachable' });
    
    const res = await request(app).get('/is-buffer/-/is-buffer-1.1.6.tgz');
    
    expect(res.status).toBe(200); // Fail open!
    expect(res.headers['content-type']).toBe('application/octet-stream');
  });
});
