'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const startServer = require('../../setup-server')
const { TestType, Severity, HttpMethod } = require('@sectester/scan')

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

t.test('POST /api/articles', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.SQL_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.HTML_INJECTION,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.STORED_CROSS_SITE_SCRIPTING,
        TestType.SECRET_TOKENS_LEAK,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/articles`,
      headers: {
        'Authorization': 'Token jwt.token.here',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        article: {
          title: 'string',
          description: 'string',
          body: 'string',
          tagList: ['string']
        }
      })
    });

  await t.resolves(promise);
});
