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

t.test('POST /api/users/login', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.BRUTE_FORCE_LOGIN,
        TestType.MASS_ASSIGNMENT,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.JWT,
        TestType.COOKIE_SECURITY
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/users/login`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'string',
          password: 'string'
        }
      })
    });

  await t.resolves(promise);
});
