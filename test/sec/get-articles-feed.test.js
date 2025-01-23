'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for GET /articles/feed', async t => {
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
        TestType.EXCESSIVE_DATA_EXPOSURE,
        'csrf',
        TestType.ID_ENUMERATION,
        TestType.JWT
      ],
      attackParamLocations: ['query', 'header']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'GET',
      url: '/api/articles/feed',
      headers: {
        Authorization: 'Bearer <token>'
      },
      query: {
        limit: 10,
        offset: 0
      }
    })

    t.end()
  })

  t.end()
})
