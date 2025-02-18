'use strict'
const t = require('tap')
const startServer = require('../../setup-server')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/scan')

let runner;

// Setup and Teardown for SecTester

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });

  await runner.init();
});

t.afterEach(() => runner.clear());

t.setTimeout(15 * 60 * 1000); // 15 minutes

// Setup and Teardown for Fastify Server

let server;
let baseUrl;

t.before(async () => {
  server = await startServer();
  baseUrl = await server.listen({ port: 0 });
});

t.teardown(() => server.close());

// Test case for GET /articles/feed

t.test('GET /articles/feed', async t => {
  const promise = runner
    .createScan({
      tests: [TestType.SQLI, TestType.XSS, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.SECRET_TOKENS_LEAK],
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
