const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/scan');
const fastify = require('fastify');
const routes = require('../../lib/routes'); // Adjust the path as necessary

let runner;
let app;
let baseUrl;

t.before(async () => {
  app = fastify({ logger: false });
  app.register(routes);
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
  t.timeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.JWT,
        TestType.SQLI,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles/feed`,
      headers: { Authorization: 'Token jwt.token.here' },
      query: { limit: '20', offset: '0' }
    });

  await t.resolves(promise);
});
