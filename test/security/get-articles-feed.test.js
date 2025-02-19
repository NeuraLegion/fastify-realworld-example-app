'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')
const startServer = require('../../setup-server')

let runner;
let server;
let baseUrl = process.env.BRIGHT_TARGET_URL || 'http://localhost:3000';

// Setup and Teardown

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();

  server = await startServer();
});

t.afterEach(async () => {
  await runner.clear();
  await server.close();
});

// Test cases

t.test('GET /api/articles/feed', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXPOSED_DATABASE_DETAILS,
        TestType.SECRET_TOKENS_LEAK
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/articles/feed`,
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      query: {
        limit: '20',
        offset: '0'
      }
    });

  await t.resolves(promise);
});
