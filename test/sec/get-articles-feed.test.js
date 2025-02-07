const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;

const baseUrl = process.env.BRIGHT_TARGET_URL || 'http://localhost:3000';

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.test('GET /articles/feed', async t => {
  t.setTimeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.JWT,
        TestType.ID_ENUMERATION
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles/feed`,
      headers: { Authorization: 'Token jwt.token.here' },
      query: { limit: '20', offset: '0' }
    });

  await t.resolves(promise);
});
