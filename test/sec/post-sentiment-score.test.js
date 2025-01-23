'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for POST /sentiment/score', async t => {
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
        TestType.CSRF,
        TestType.XSS,
        TestType.SQLI,
        'insecure_output_handling',
        'excessive_data_exposure'
      ],
      attackParamLocations: ['body']
    })
    .threshold('MEDIUM')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'POST',
      url: `${server.url}/sentiment/score`,
      headers: {
        Authorization: 'Bearer <token>'
      },
      body: {
        content: '<string>'
      }
    })

    t.end()
  })

  t.end()
})
