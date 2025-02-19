'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod } = require('@sectester/scan')
const startServer = require('../setup-server')

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

t.test('PUT /api/articles/:slug', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.HTML_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/articles/test-slug`,
      headers: {
        'Authorization': 'Token jwt.token.here',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        article: {
          title: 'string',
          description: 'string',
          body: 'string'
        }
      })
    });

  await t.resolves(promise);
});
