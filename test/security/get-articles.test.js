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

t.setTimeout(15 * 60 * 1000); // 15 minutes

// Security Test Cases

t.test('GET /api/articles', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.CROSS_SITE_SCRIPTING,
        TestType.HTML_INJECTION,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/articles`,
      query: {
        tag: 'string',
        author: 'string',
        favorited: 'string',
        limit: '20',
        offset: '0'
      }
    });

  await t.resolves(promise);
});
