// Covers the `X-Service-Token` contract with courthive-persons.
//
// persons requires the header on every route except /health, so a client that silently stops sending it turns every HiveID signup
// into a 401 at the identity step. There was no spec for this client before;
// these tests exist so the header cannot be dropped unnoticed.

import { PersonsClient } from './persons-client.service';
import type { MockInstance } from 'vitest';

function mockResponse(body: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => body } as Response;
}

describe('PersonsClient', () => {
  let client: PersonsClient;
  let fetchSpy: MockInstance;

  beforeEach(() => {
    process.env.PERSONS_BASE_URL = 'http://test-persons:3100';
    client = new PersonsClient();
    fetchSpy = vi.spyOn(globalThis, 'fetch') as any;
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    delete process.env.PERSONS_SERVICE_TOKEN;
    delete process.env.PERSONS_BASE_URL;
  });

  it('sends X-Service-Token on resolve, alongside the JSON content type', async () => {
    process.env.PERSONS_SERVICE_TOKEN = 'sekrit';
    fetchSpy.mockResolvedValueOnce(mockResponse({ status: 'minted', personId: 'p-1' }));

    const result = await client.resolve({ standardFamilyName: 'Allen' });

    expect(result).toEqual({ status: 'minted', personId: 'p-1' });
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('http://test-persons:3100/persons/resolve');
    expect(init.headers['X-Service-Token']).toBe('sekrit');
    expect(init.headers['Content-Type']).toBe('application/json');
  });

  it('sends X-Service-Token on getById', async () => {
    process.env.PERSONS_SERVICE_TOKEN = 'sekrit';
    fetchSpy.mockResolvedValueOnce(mockResponse({ person: {}, aliases: [] }));

    await client.getById('p-1');

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('http://test-persons:3100/persons/p-1');
    expect(init.headers['X-Service-Token']).toBe('sekrit');
  });

  it('omits the header when the secret is unset rather than sending an empty one', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ status: 'incomplete' }));
    await client.resolve({});
    expect(fetchSpy.mock.calls[0][1].headers).not.toHaveProperty('X-Service-Token');
  });

  it('reads the secret at call time so rotation does not need a restart', async () => {
    fetchSpy.mockResolvedValue(mockResponse({ status: 'incomplete' }));
    await client.resolve({});
    expect(fetchSpy.mock.calls[0][1].headers).not.toHaveProperty('X-Service-Token');
    process.env.PERSONS_SERVICE_TOKEN = 'rotated';
    await client.resolve({});
    expect(fetchSpy.mock.calls[1][1].headers['X-Service-Token']).toBe('rotated');
  });

  it('still URL-encodes the personId and returns null on 404', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({}, false, 404));
    const result = await client.getById('with/slash');
    expect(result).toBeNull();
    expect(fetchSpy.mock.calls[0][0]).toBe('http://test-persons:3100/persons/with%2Fslash');
  });

  it('throws on a non-OK response that is not 404', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({}, false, 401));
    await expect(client.getById('p-1')).rejects.toThrow('persons getById failed: HTTP 401');
  });
});
