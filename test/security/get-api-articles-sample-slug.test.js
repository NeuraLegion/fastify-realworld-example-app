import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity } from '@sectester/scan/src/models/Severity';
import { AttackParamLocation } from '@sectester/scan/src/models/AttackParamLocation';
import { HttpMethod } from '@sectester/scan/src/models/HttpMethod';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('GET /api/articles/sample-slug', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'excessive_data_exposure', 'bopla', 'mass_assignment'],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/articles/sample-slug`
    });
});
