// The Node floor is the ecosystem minimum: Node 24, the LTS line.
// Node 22 is maintenance-only and reaches end of life in April 2027.
//
// The floor is reported, not assumed. NestJS 12 is ESM-only: @nestjs/common@12
// publishes "type": "module" with no `require` condition in its exports map, and
// this service is CommonJS, so it reaches Nest through `require(esm)`. That is
// unflagged throughout 24 (on 22 it needed 22.12 — measured on
// competition-factory-server: 22.0 and 22.11 fail every Nest import with
// ERR_REQUIRE_ESM). The minor is kept so a later floor can name one again.
//
// Keep this constant and package.json's `engines.node` in step; the spec reads
// both.
export const NODE_FLOOR = { major: 24, minor: 0 } as const;
export const NODE_FLOOR_RANGE = NODE_FLOOR.minor
  ? `>=${NODE_FLOOR.major}.${NODE_FLOOR.minor}`
  : `>=${NODE_FLOOR.major}`;

export type NodeFloorReport = {
  version: string;
  minimum: string;
  satisfied: boolean;
};

export function checkNodeFloor(version: string = process.version): NodeFloorReport {
  const [major, minor] = version
    .replace(/^v/, '')
    .split('.')
    .map((part) => parseInt(part, 10));

  const satisfied =
    Number.isFinite(major) &&
    Number.isFinite(minor) &&
    (major > NODE_FLOOR.major || (major === NODE_FLOOR.major && minor >= NODE_FLOOR.minor));

  return { version, minimum: NODE_FLOOR_RANGE, satisfied };
}
