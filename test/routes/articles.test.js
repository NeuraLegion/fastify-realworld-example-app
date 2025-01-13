'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

const configuration = { hostname: 'app.brightsec.com' }
const runner = new SecRunner(configuration)

// Initialize the runner
before(async () => {
  await runner.init();
});

// Clear the runner after tests
after(async () => {
  await runner.clear();
});

async function runSecurityTests(target, tests) {
  const scan = runner.createScan({ tests });
  await scan.run(target);
}

// Security tests

// Test for GET /articles/:slug
runSecurityTests({
  method: 'GET',
  url: 'http://localhost:3000/articles/test-article'
}, [
  TestType.BROKEN_ACCESS_CONTROL,
  TestType.EXCESSIVE_DATA_EXPOSURE,
  TestType.ID_ENUMERATION,
  TestType.HTTP_METHOD_FUZZING,
  TestType.XSS
]).catch(console.error);

// Test for POST /articles
runSecurityTests({
  method: 'POST',
  url: 'http://localhost:3000/articles',
  headers: { 'Authorization': 'Token jwt.token.here' },
  body: {
    mimeType: 'application/json',
    text: JSON.stringify({
      article: {
        title: 'string',
        description: 'string',
        body: 'string',
        tagList: ['string']
      }
    })
  }
}, [
  TestType.JWT,
  TestType.CSRF,
  TestType.MASS_ASSIGNMENT,
  TestType.XSS,
  TestType.SQLI
]).catch(console.error);

// Test for POST /articles/:slug/favorite
runSecurityTests({
  method: 'POST',
  url: 'http://localhost:3000/articles/:slug/favorite',
  headers: { Authorization: 'Token jwt.token.here' }
}, [
  TestType.JWT,
  TestType.CSRF,
  TestType.BROKEN_ACCESS_CONTROL,
  TestType.HTTP_METHOD_FUZZING
]).catch(console.error);

// Test for DELETE /articles/:slug/favorite
runSecurityTests({
  method: 'DELETE',
  url: 'http://localhost:3000/articles/:slug/favorite',
  headers: { Authorization: 'Token jwt.token.here' }
}, [
  TestType.JWT,
  'broken_access_control',
  TestType.CSRF,
  TestType.HTTP_METHOD_FUZZING
]).catch(console.error);

// Functional tests

t.test('GET /articles/:slug should not have vulnerabilities', async (t) => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/articles/test-article'
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')
  t.end()
});

t.test('create article', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/api/articles',
    headers: { 'Authorization': 'Token jwt.token.here' },
    payload: {
      article: {
        title: 'Test Article',
        description: 'Test Description',
        body: 'Test Body',
        tagList: ['test']
      }
    }
  })

  t.equal(response.statusCode, 201, 'returns a status code of 201 Created')
  t.end()
});

t.test('favorite article endpoint security tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/articles/:slug/favorite',
    headers: { Authorization: 'Token jwt.token.here' }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')
  t.end()
});

t.test('delete article favorite with security tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'DELETE',
    url: '/articles/:slug/favorite',
    headers: { Authorization: 'Token jwt.token.here' }
  })
  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')
  t.end()
});
