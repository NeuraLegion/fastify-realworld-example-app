'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for DELETE /articles/:slug/comments/:id', async t => {
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
        TestType.BROKEN_ACCESS_CONTROL,
        'csrf',
        TestType.ID_ENUMERATION,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.XSS
      ],
      attackParamLocations: ['path', 'header']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'DELETE',
      url: 'http://localhost:3000/articles/:slug/comments/:id',
      headers: {
        Authorization: 'Token jwt.token.here'
      }
    })

    t.end()
  })

  t.end()
})
