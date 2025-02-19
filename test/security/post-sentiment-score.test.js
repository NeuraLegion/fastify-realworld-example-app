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

t.test('POST /api/sentiment/score', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.EXPOSED_DATABASE_DETAILS,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SECRET_TOKENS_LEAK,
        TestType.SERVER_SIDE_REQUEST_FORGERY
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/sentiment/score`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        content: 'string'
      })
    });

  await t.resolves(promise);
});
