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

test('DELETE /api/articles/sample-article/comments/1', async t => {
  const promise = runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.SQLI, TestType.CSRF, TestType.ID_ENUMERATION],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.DELETE,
      url: `${baseUrl}/api/articles/sample-article/comments/1`,
      headers: { Authorization: 'Token sample.jwt.token' }
    });

  await t.notThrowsAsync(promise);
});
