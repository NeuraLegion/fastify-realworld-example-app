'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan')

let runner;
let server;
let baseUrl;

t.before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();

  server = await startServer();
  baseUrl = server.server.address().port;
});

t.afterEach(() => runner.clear());

t.teardown(() => server.close());

t.test('GET /articles/feed', async t => {
  const promise = runner
    .createScan({
      tests: [
        TestType.SQLI,
        TestType.XSS,
        TestType.CSRF,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.ID_ENUMERATION
      ],
      attackParamLocations: [
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles/feed`,
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      query: {
        limit: '20',
        offset: '0'
      }
    });

  t.rejects(promise)
  t.end()
});
