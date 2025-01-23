'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /articles/:slug', async t => {
  let server
  t.before(async () => {
    server = await startServer()
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
    await server.close()
  })

  t.test('GET /articles/:slug', async t => {
    await runner.createScan({
      tests: [
        TestType.ID_ENUMERATION,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        'CSRF',
        TestType.XSS
      ],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: 'GET',
      url: `${server.baseUrl}/articles/test-slug`
    })

    t.end()
  })

  t.end()
})