'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod } = require('@sectester/scan')
const startServer = require('../../setup-server')

let runner;
let server;

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

t.test('DELETE /api/articles/example-slug/favorite', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.SQL_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.BROKEN_JWT_AUTHENTICATION,
        TestType.EXPOSED_DATABASE_DETAILS
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/articles/example-slug/favorite`,
      headers: {
        Authorization: 'Token jwt.token.here'
      }
    });

  await t.resolves(promise);
});
