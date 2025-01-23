'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for GET /profiles/johndoe', async t => {
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

    t.test('GET /profiles/johndoe', async t => {
      await runner.createScan({
        tests: [
          TestType.BROKEN_ACCESS_CONTROL,
          'excessive_data_exposure',
          TestType.JWT,
          'id_enumeration'
        ],
        attackParamLocations: ['header']
      })
      .threshold('medium')
      .timeout(TEST_TIMEOUT)
      .run({
        method: 'GET',
        url: '/profiles/johndoe',
        headers: {
          Authorization: 'Bearer <token>'
        }
      })

      t.end()
    })

    t.end()
  })

  t.end()
})
