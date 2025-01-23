'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for POST /articles/:slug/comments', async t => {
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
        TestType.JWT,
        TestType.XSS,
        TestType.CSRF,
        TestType.SQLI,
        'broken_access_control',
        'insecure_output_handling'
      ],
      attackParamLocations: ['body']
    })
    .threshold('MEDIUM')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'POST',
      url: 'http://localhost:3000/articles/:slug/comments',
      headers: {
        'Authorization': 'Token jwt.token.here',
        'Content-Type': 'application/json'
      },
      body: {
        comment: {
          body: 'string'
        }
      }
    })

    t.end()
  })

  t.end()
})
