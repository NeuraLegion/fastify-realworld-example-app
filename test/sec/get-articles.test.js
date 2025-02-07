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
  baseUrl = `http://localhost:${server.server.address().port}`;
});

t.afterEach(() => runner.clear());

t.teardown(() => server.close());

t.test('GET /articles', async t => {
  const promise = runner
    .createScan({
      tests: [TestType.SQLI, TestType.XSS, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.ID_ENUMERATION, TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/articles`,
      query: {
        tag: 'string',
        author: 'string',
        favorited: 'string',
        limit: '20',
        offset: '0'
      }
    });

  t.rejects(promise)
  t.end()
});
