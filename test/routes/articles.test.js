'use strict'
const t = require('tap')
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');
const startServer = require('../setup-server')

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

async function createSecRunner() {
  const runner = new SecRunner(configuration);
  await runner.init();
  return runner;
}

// Security tests
async function runSecurityTests() {
  const runner = await createSecRunner();
  const scan = runner.createScan({ tests: [TestType.SQLI, TestType.XSS, TestType.BROKEN_ACCESS_CONTROL] });

  const targets = [
    {
      method: 'GET',
      url: 'http://localhost:3000/api/articles',
      query: { tag: 'test', author: 'test', favorited: 'test', limit: 10, offset: 0 }
    },
    {
      method: 'GET',
      url: 'http://localhost:3000/api/articles/test-article'
    },
    {
      method: 'POST',
      url: 'http://localhost:3000/api/articles',
      headers: { 'Authorization': 'Token jwt.token.here' },
      body: { article: { title: 'string', description: 'string', body: 'string', tagList: ['string'] } }
    },
    {
      method: 'PUT',
      url: 'http://localhost:3000/api/articles/{slug}',
      headers: { Authorization: 'Token jwt.token.here' },
      body: { article: { title: 'string', description: 'string', body: 'string' } }
    },
    {
      method: 'DELETE',
      url: 'http://localhost:3000/api/articles/test-article',
      headers: { Authorization: 'Token jwt.token.here' }
    },
    {
      method: 'POST',
      url: 'http://localhost:3000/api/articles/{slug}/favorite',
      headers: { Authorization: 'Token jwt.token.here' },
      body: {}
    },
    {
      method: 'DELETE',
      url: 'http://localhost:3000/api/articles/{slug}/favorite',
      headers: { Authorization: 'Token jwt.token.here' }
    }
  ];

  for (const target of targets) {
    await scan.run(target).catch(console.error);
  }

  await runner.clear();
}

runSecurityTests().catch(console.error);

// Functional tests

// Test for GET /api/articles
 t.test('requests the "/api/articles" route', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/api/articles',
    query: { tag: 'test', author: 'test', favorited: 'test', limit: 10, offset: 0 }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})

// Test for GET /api/articles/{slug}
 t.test('requests the "/api/articles/{slug}" route', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/api/articles/test-article'
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})

// Test for POST /api/articles
 t.test('requests the "/api/articles" route with POST', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/api/articles',
    headers: { 'Authorization': 'Token jwt.token.here' },
    payload: { article: { title: 'string', description: 'string', body: 'string', tagList: ['string'] } }
  })

  t.equal(response.statusCode, 201, 'returns a status code of 201')
  t.end()
})

// Test for PUT /api/articles/{slug}
 t.test('requests the "/api/articles/{slug}" route with PUT', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'PUT',
    url: '/api/articles/{slug}',
    headers: { Authorization: 'Token jwt.token.here' },
    payload: { article: { title: 'string', description: 'string', body: 'string' } }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})

// Test for DELETE /api/articles/{slug}
 t.test('requests the "/api/articles/{slug}" route with DELETE', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'DELETE',
    url: '/api/articles/test-article',
    headers: { Authorization: 'Token jwt.token.here' }
  })

  t.equal(response.statusCode, 204, 'returns a status code of 204')
  t.end()
})

// Test for POST /api/articles/{slug}/favorite
 t.test('requests the "/api/articles/{slug}/favorite" route with POST', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/api/articles/{slug}/favorite',
    headers: { Authorization: 'Token jwt.token.here' },
    payload: {}
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})

// Test for DELETE /api/articles/{slug}/favorite
 t.test('requests the "/api/articles/{slug}/favorite" route with DELETE', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'DELETE',
    url: '/api/articles/{slug}/favorite',
    headers: { Authorization: 'Token jwt.token.here' }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200')
  t.end()
})
