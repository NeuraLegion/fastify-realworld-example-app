'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

const configuration = { hostname: 'app.brightsec.com' }

async function runSecurityTests() {
  const runner = new SecRunner(configuration)
  await runner.init()

  const scan1 = runner.createScan({ tests: [TestType.SQLI, TestType.XSS] })
  await scan1.run({
    method: 'GET',
    url: 'http://localhost:3000/articles/example-article/comments'
  })

  const scan2 = runner.createScan({ tests: [TestType.XSS, TestType.SQLI] })
  await scan2.run({
    method: 'POST',
    url: '/articles/example-article/comments',
    headers: { Authorization: 'Token example.jwt.token' },
    body: { comment: { body: 'This is a comment.' } }
  })

  const scan3 = runner.createScan({ tests: [TestType.BROKEN_ACCESS_CONTROL] })
  await scan3.run({
    method: 'DELETE',
    url: 'https://localhost:3000/articles/example-article/comments/1',
    headers: { Authorization: 'Token example.jwt.token' }
  })

  await runner.clear()
}

runSecurityTests().catch(console.error)

// Functional tests

t.test('get comments for an article', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/articles/example-article/comments'
  })
  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')
  t.end()
})

t.test('post comment with XSS and SQLi tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/articles/example-article/comments',
    headers: { Authorization: 'Token example.jwt.token' },
    payload: { comment: { body: 'This is a comment.' } }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')
  t.end()
})

t.test('delete comment without proper authorization', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'DELETE',
    url: '/articles/example-article/comments/1',
    headers: { Authorization: 'Token example.jwt.token' }
  })
  t.equal(response.statusCode, 403, 'returns a status code of 403 Forbidden')
  t.end()
})
