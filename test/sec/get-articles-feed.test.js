const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');
const startServer = require('../setup-server');

let runner;
let app;
let baseUrl;

t.before(async () => {
  app = await startServer();
  baseUrl = await app.listen({ port: 0 });
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();
});

t.afterEach(() => runner.clear());

t.teardown(() => app.close());

t.test('GET /articles/feed', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.JWT,
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION
      ],
      attackParamLocations: [
        AttackParamLocation.HEADER,
        AttackParamLocation.QUERY
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles/feed`,
      headers: { Authorization: 'Token jwt.token.here' },
      query: { limit: '20', offset: '0' }
    });

  t.rejects(promise);
  t.end();
});
