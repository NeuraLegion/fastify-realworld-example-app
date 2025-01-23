'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for DELETE /articles/example-article/comments/1', async t => {
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

    t.test('DELETE /articles/example-article/comments/1', async t => {
      await runner.createScan({
        tests: [
          TestType.BROKEN_ACCESS_CONTROL,
          'csrf',
          'id_enumeration'
        ],
        attackParamLocations: ['path']
      })
      .threshold('medium')
      .timeout(TEST_TIMEOUT)
      .run({
        method: 'DELETE',
        url: '/articles/example-article/comments/1'
      })

      t.end()
    })

    t.end()
  })

  t.end()
})
