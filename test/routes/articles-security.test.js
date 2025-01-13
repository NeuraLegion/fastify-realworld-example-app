'use strict'
const t = require('tap')
const { SecRunner, TestType } = require('@sectester/runner')
const startServer = require('../setup-server')

const configuration = { hostname: 'app.brightsec.com' }

let runner

// Initialize SecRunner before tests

t.before(async () => {
  runner = new SecRunner(configuration)
  await runner.init()
})

// Clear SecRunner after tests

t.teardown(async () => {
  await runner.clear()
})

// Test for PUT /articles/:slug endpoint

t.test('security tests for PUT /articles/:slug', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const scan = runner.createScan({
    tests: [
      TestType.JWT,
      TestType.CSRF,
      TestType.MASS_ASSIGNMENT,
      TestType.XSS,
      TestType.SQLI
    ]
  })

  await scan.run({
    method: 'PUT',
    url: 'http://localhost:3000/api/articles/:slug',
    headers: { Authorization: 'Token jwt.token.here' },
    body: { article: { title: 'string', description: 'string', body: 'string' } }
  })

  t.pass('security tests completed for PUT /articles/:slug')
  t.end()
})

// Test for DELETE /articles/:slug endpoint

t.test('DELETE /articles/:slug security tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const scan = runner.createScan({
    tests: [
      TestType.JWT,
      TestType.BROKEN_ACCESS_CONTROL,
      TestType.CSRF,
      TestType.HTTP_METHOD_FUZZING
    ]
  })

  await scan.run({
    method: 'DELETE',
    url: 'http://localhost:3000/api/articles/test-article',
    headers: {
      Authorization: 'Token jwt.token.here'
    }
  })

  t.pass('Security tests completed for DELETE /articles/:slug')
  t.end()
})
