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

t.test('DELETE /articles/:slug', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.AUTHENTICATION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: 'http://localhost:3000/articles/example-slug',
      headers: {
        Authorization: 'Token example-token'
      }
    });

  await t.resolves(promise);
});
