'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner


t.test('setup', async t => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.end()
})

t.teardown(async () => {
  await runner.clear()
})

t.test('GET /api/articles/{slug}', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [
      TestType.BROKEN_ACCESS_CONTROL,
      TestType.EXCESSIVE_DATA_EXPOSURE,
      'id_enumeration',
      TestType.HTTP_METHOD_FUZZING,
      TestType.SQLI,
      TestType.XSS
    ],
    attackParamLocations: [AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/api/articles/test-slug`
  })

  t.end()
})
