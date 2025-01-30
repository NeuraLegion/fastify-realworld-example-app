const t = require('tap');
const startServer = require('../setup-server');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let runner;
let app;
let baseUrl;

t.before(async () => {
  app = await startServer();
  await app.ready();

  const address = app.server.address();
  const protocol = app.server instanceof https.Server ? 'https' : 'http';
  baseUrl = `${protocol}://localhost:${address.port}`;
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());
t.after(() => app.close());

test('POST /users/login', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.BRUTE_FORCE_LOGIN,
        TestType.CSRF,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.JWT
      ],
      attackParamLocations: [
        AttackParamLocation.BODY
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/users/login`,
      headers: {},
      body: {
        user: {
          email: 'string',
          password: 'string'
        }
      }
    });

  await t.notThrowsAsync(promise);
});
