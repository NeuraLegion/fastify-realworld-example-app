'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/scan')
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

// Security Test Cases

t.test('DELETE /api/articles/:slug/favorite', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.BROKEN_JWT_AUTHENTICATION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.HTTP_METHOD_FUZZING,
        TestType.IMPROPER_ASSET_MANAGEMENT,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SQL_INJECTION,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL}/api/articles/:slug/favorite`,
      headers: {
        Authorization: 'Token jwt.token.here'
      }
    });

  await t.resolves(promise);
});
