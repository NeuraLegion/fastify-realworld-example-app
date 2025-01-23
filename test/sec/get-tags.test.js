'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for GET /tags', async t => {
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

    t.test('excessive_data_exposure', async t => {
      await runner.createScan({
        tests: ['excessive_data_exposure'],
        attackParamLocations: ['query', 'body', 'path']
      }).run({
        method: 'GET',
        url: '/api/tags'
      })
      t.end()
    })

    t.test('improper_asset_management', async t => {
      await runner.createScan({
        tests: ['improper_asset_management'],
        attackParamLocations: ['query', 'body', 'path']
      }).run({
        method: 'GET',
        url: '/api/tags'
      })
      t.end()
    })

    t.end()
  })

  t.end()
})
