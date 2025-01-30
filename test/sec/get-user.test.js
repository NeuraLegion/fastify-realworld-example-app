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

test('GET /user', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.JWT,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/user`,
      headers: { Authorization: 'Token jwt.token.here' }
    });

  await t.notThrowsAsync(promise);
});
