'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const startServer = require('../setup-server')
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan')

let runner;

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.test('GET /api/articles/feed', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, TestType.EXCESSIVE_DATA_EXPOSURE],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .run({
      method: HttpMethod.GET,
      url: 'http://localhost:3000/api/articles/feed',
      headers: { Authorization: 'Token jwt.token.here' },
      query: { limit: '20', offset: '0' }
    });

  t.end();
});
