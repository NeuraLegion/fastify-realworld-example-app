'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod } = require('@sectester/scan')
const startServer = require('../../setup-server')

let runner;
let server;
let baseUrl;

// Setup and Teardown

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();

  server = await startServer();
  baseUrl = process.env.BRIGHT_TARGET_URL || await server.listen(0);
});

t.afterEach(async () => {
  await runner.clear();
  await server.close();
});

t.setTimeout(15 * 60 * 1000); // 15 minutes

// Security tests for GET /api/articles/:slug/comments

t.test('GET /api/articles/:slug/comments', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [TestType.SQL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.FULL_PATH_DISCLOSURE],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/api/articles/test-article/comments`
    });

  await t.resolves(promise);
});
