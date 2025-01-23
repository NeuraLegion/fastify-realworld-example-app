'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for POST /articles/example-article/comments', async t => {
  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
  })

  t.test('initialize server', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    await runner.createScan({
      tests: [
        TestType.CSRF,
        TestType.XSS,
        'stored_xss',
        TestType.SQLI,
        'insecure_output_handling',
        'broken_access_control'
      ],
      attackParamLocations: ['body']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'POST',
      url: '/articles/example-article/comments',
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        comment: {
          body: 'This is a comment.'
        }
      }
    })

    t.end()
  })

  t.end()
})
