const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
let app;
let baseUrl;

// Setup hooks for initializing the application and SecTester

t.before(async () => {
  app = require('../../lib/server'); // Adjust the path to the actual server file

  await app.ready();

  baseUrl = app.server.address().port;
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.after(() => app.close());

// Placeholder for test cases

test('DELETE /api/articles/:slug', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.ID_ENUMERATION
      ],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${baseUrl}/api/articles/test-slug`,
      headers: { Authorization: 'Token jwt.token.here' }
    });

  await t.notThrowsAsync(promise);
});
