'use strict'
const t = require('tap')
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');
const startServer = require('../setup-server')

const configuration = new Configuration({ hostname: 'app.brightsec.com' });
const runner = new SecRunner(configuration);

async function runSecurityTests() {
  await runner.init();

  const scan = runner.createScan({ tests: [TestType.SQLI, TestType.XSS, TestType.BROKEN_ACCESS_CONTROL] });

  const target = {
    method: 'GET',
    url: 'http://localhost:3000/api/articles/feed',
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 10, offset: 0 }
  };

  await scan.run(target);
  await runner.clear();
}

runSecurityTests().catch(console.error);


// Functional test

t.test('requests the "/articles/feed" route', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/api/articles/feed',
    headers: { 'Authorization': 'Token jwt.token.here' },
    query: { limit: 10, offset: 0 }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})