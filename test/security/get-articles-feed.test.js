'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')
const startServer = require('../setup-server')

let runner;
let server;
let baseUrl;

t.before(async () => {
  server = await startServer();
  baseUrl = await server.listen({ port: 0 });
});

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();
});

t.afterEach(() => runner.clear());

t.teardown(() => server.close());

t.setTimeout(15 * 60 * 1000);

t.test('GET /api/articles/feed', async t => {

  const promise = runner
    .createScan({
      tests: [TestType.JWT, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.ID_ENUMERATION, TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/articles/feed`,
      headers: { Authorization: 'Token jwt.token.here' },
      query: { limit: '20', offset: '0' }
    });

  await t.resolves(promise);
});
