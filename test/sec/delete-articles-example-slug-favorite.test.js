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

test('DELETE /articles/example-slug/favorite', async t => {
  const promise = runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.SQLI, TestType.ID_ENUMERATION, TestType.CSRF],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.DELETE,
      url: `${baseUrl}/articles/example-slug/favorite`,
      headers: { Authorization: 'Bearer example-token' }
    });

  await t.notThrowsAsync(promise);
});
