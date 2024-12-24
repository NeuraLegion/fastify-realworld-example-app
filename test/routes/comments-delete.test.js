'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity } = require('@sectester/runner')

const configuration = { hostname: 'app.brightsec.com' }

// Test for DELETE /articles/example-article/comments/1

t.test('DELETE /articles/example-article/comments/1 should not have broken access control', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const runner = new SecRunner(configuration)
  await runner.init()

  const scan = runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL],
    threshold: Severity.MEDIUM,
    timeout: 300000 // 5 minutes
  })

  await scan.run({
    method: 'DELETE',
    url: 'https://localhost:8000/articles/example-article/comments/1',
    headers: { Authorization: 'Bearer <token>' }
  })

  await runner.clear()
  t.end()
})
