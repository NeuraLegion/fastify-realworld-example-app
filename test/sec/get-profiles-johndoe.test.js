'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('GET /profiles/johndoe', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'excessive_data_exposure'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/profiles/johndoe`,
    headers: {
      'Authorization': 'Bearer <token>'
    }
  })

  t.end()
})