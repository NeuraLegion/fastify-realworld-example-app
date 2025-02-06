const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
let app;
let baseUrl;

// Setup hooks for initializing the application and SecTester

t.before(async () => {
  app = require('../../lib/server'); // Adjust the path to your server file

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

// Security test for GET /api/articles/feed

test('GET /api/articles/feed', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.JWT,
        TestType.EXCESSIVE_DATA_EXPOSURE
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: HttpMethod.GET,
      url: `http://localhost:${baseUrl}/api/articles/feed`,
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      query: {
        limit: '20',
        offset: '0'
      }
    });

  await t.notThrowsAsync(promise);
});
