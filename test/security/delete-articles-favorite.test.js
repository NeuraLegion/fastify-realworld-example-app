'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod } = require('@sectester/runner')
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

t.test('DELETE /articles/example-slug/favorite', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.EXPOSED_DATABASE_DETAILS
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/articles/example-slug/favorite`,
      headers: {
        Authorization: 'Token example-token'
      }
    });

  await t.resolves(promise);
});
