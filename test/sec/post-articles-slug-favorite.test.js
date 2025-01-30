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

test('POST /articles/:slug/favorite', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.JWT,
        TestType.BRUTE_FORCE_LOGIN,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.STORED_XSS
      ],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY, AttackParamLocation.PATH]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/articles/:slug/favorite`,
      headers: { Authorization: 'Token jwt.token.here' },
      body: {}
    });

  await t.notThrowsAsync(promise);
});
