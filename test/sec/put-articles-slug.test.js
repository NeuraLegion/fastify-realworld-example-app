'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for PUT /articles/:slug', async t => {
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
        TestType.BROKEN_ACCESS_CONTROL,
        'csrf',
        TestType.XSS,
        TestType.SQLI,
        'insecure_output_handling',
        TestType.JWT
      ],
      attackParamLocations: ['body']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'PUT',
      url: '/api/articles/:slug',
      headers: {
        Authorization: 'Bearer <token>'
      },
      body: {
        article: {
          title: 'string',
          description: 'string',
          body: 'string'
        }
      }
    })

    t.end()
  })

  t.end()
})
