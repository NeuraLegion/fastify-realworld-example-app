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

test('POST /articles/:slug/comments', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.MASS_ASSIGNMENT,
        TestType.STORED_XSS,
        TestType.JWT,
        TestType.EXCESSIVE_DATA_EXPOSURE
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER, AttackParamLocation.PATH]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/articles/:slug/comments`,
      headers: { Authorization: 'Token jwt.token.here' },
      body: { comment: { body: 'string' } }
    });

  await t.notThrowsAsync(promise);
});
