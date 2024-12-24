'use strict'
const t = require('tap');
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType, Severity } = require('@sectester/scan');
const startServer = require('../setup-server');

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

async function runSecurityTests() {
  const runner = new SecRunner(configuration);
  await runner.init();

  const scan = runner.createScan({
    tests: [TestType.XSS, TestType.SQLI],
    threshold: Severity.MEDIUM,
    timeout: 300000, // 5 minutes
  });

  const server = await startServer();

  // Test case 1: GET request
  await scan.run({
    method: 'GET',
    url: 'http://localhost:3000/articles/example-article/comments'
  });

  // Test case 2: POST request
  await scan.run({
    method: 'POST',
    url: 'https://localhost:8000/articles/example-article/comments',
    headers: { 'Authorization': 'Bearer <token>' },
    body: { comment: { body: 'This is a comment.' } }
  });

  await runner.clear();
  server.close();
}

runSecurityTests().catch(err => {
  console.error(err);
  process.exit(1);
});

// TAP test for POST request
t.test('post comment with security tests', async t => {
  const server = await startServer();
  t.teardown(() => server.close());

  const response = await server.inject({
    method: 'POST',
    url: '/articles/example-article/comments',
    headers: { 'Authorization': 'Bearer <token>' },
    payload: { comment: { body: 'This is a comment.' } }
  });

  t.equal(response.statusCode, 200, 'returns a status code of 200 OK');
  t.end();
});
