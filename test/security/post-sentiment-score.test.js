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

test('POST /sentiment/score', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['excessive_data_exposure', 'mass_assignment', 'xss', 'csrf', 'nosql'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/sentiment/score`,
      body: JSON.stringify({ content: "Sample text to analyze sentiment." }),
      headers: { 'Content-Type': 'application/json' }
    });
});
