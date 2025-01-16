'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('SecTester integration for POST /api/articles/example-article/comments', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  // Clear SecTester runner after each test
  t.afterEach(() => runner.clear())

  // Security test case
  t.test('POST /api/articles/example-article/comments', async t => {
    await runner
      .createScan({
        tests: [TestType.CSRF, TestType.XSS, TestType.BROKEN_ACCESS_CONTROL, 'EXCESSIVE_DATA_EXPOSURE'],
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.MEDIUM)
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: 'http://localhost:3000/api/articles/example-article/comments',
        headers: [{ name: 'Authorization', value: 'Bearer <token>' }],
        postData: {
          mimeType: 'application/json',
          text: JSON.stringify({ comment: { body: 'This is a comment.' } })
        }
      })

    t.end()
  })

  t.end()
})