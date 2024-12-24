'use strict'
const t = require('tap')
const { Configuration } = require('@sectester/core');
const { SecRunner } = require('@sectester/runner');
const { TestType, Severity } = require('@sectester/scan');
const startServer = require('../setup-server')

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

async function runSecurityTests() {
  const runner = new SecRunner(configuration);
  await runner.init();

  const scan = runner.createScan({
    tests: [TestType.SQLI, TestType.XSS],
    threshold: Severity.MEDIUM,
    timeout: 300000, // 5 minutes
  });

  const target = {
    method: 'GET',
    url: 'https://localhost:3000/articles/feed',
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 10, offset: 0 }
  };

  await scan.run(target);
  await runner.clear();
}

runSecurityTests().catch(console.error);

// Regular functional test

 t.test('requests the "/articles/feed" route', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/articles/feed',
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 10, offset: 0 }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})