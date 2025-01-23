'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for DELETE /profiles/johndoe/follow', async t => {
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
        TestType.ID_ENUMERATION,
        TestType.JWT
      ],
      attackParamLocations: ['header']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'DELETE',
      url: '/profiles/johndoe/follow',
      headers: {
        Authorization: 'Bearer <token>'
      }
    })

    t.end()
  })

  t.end()
})
