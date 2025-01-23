'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /profiles/:username', async t => {
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

  t.test('GET /profiles/:username', async t => {
    await runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        'id_enumeration',
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.XSS
      ],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: 'GET',
      url: `${server.baseUrl}/profiles/testuser`
    })

    t.end()
  })

  t.end()
})