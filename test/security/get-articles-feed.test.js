'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const startServer = require('../../setup-server')
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan')

let runner;
let server;
let baseUrl;

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();

  server = await startServer();
  baseUrl = await server.listen({ port: 0 });
});

t.afterEach(async () => {
  await runner.clear();
  await server.close();
});

t.test('GET /articles/feed', async t => {
  t.setTimeout(15 * 60 * 1000);

  const promise = runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.HTTP_METHOD_FUZZING,
        TestType.ID_ENUMERATION,
        TestType.JWT,
        TestType.SQLI
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
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
