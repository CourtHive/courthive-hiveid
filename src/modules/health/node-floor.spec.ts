import { NODE_FLOOR_RANGE, checkNodeFloor } from './node-floor';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The point of this spec is that the check is a DETECTION, not a default: every
// version below the floor is asserted explicitly, so a regression to a looser
// comparison fails here rather than in production.
describe('checkNodeFloor', () => {
  it('declares the floor that engines.node declares', () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'));
    expect(NODE_FLOOR_RANGE).toBe('>=24');
    expect(pkg.engines.node).toBe(NODE_FLOOR_RANGE);
  });

  it.each(['v24.0.0', 'v24.22.0', 'v25.0.0', 'v26.8.1'])('accepts %s', (version) => {
    expect(checkNodeFloor(version).satisfied).toBe(true);
  });

  it.each(['v23.11.0', 'v22.22.1', 'v22.12.0', 'v21.7.3', 'v20.19.0'])('rejects %s', (version) => {
    expect(checkNodeFloor(version).satisfied).toBe(false);
  });

  it('reports the version it was given alongside the minimum', () => {
    expect(checkNodeFloor('v22.22.1')).toEqual({ version: 'v22.22.1', minimum: '>=24', satisfied: false });
  });

  it('refuses an unparseable version rather than defaulting it to ok', () => {
    expect(checkNodeFloor('not-a-version').satisfied).toBe(false);
  });

  it('reads process.version when given no argument', () => {
    expect(checkNodeFloor().version).toBe(process.version);
  });
});
