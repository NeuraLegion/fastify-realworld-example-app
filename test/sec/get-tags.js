'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner } = require('@sectester/runner')
const { TestType } = require('@sectester/scan')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('GET /api/tags security tests', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  // Clear SecTester runner after each test
  t.teardown(() => runner.clear())

  // Run security tests
  await runner.createScan({
    tests: [TestType.EXCESSIVE_DATA_EXPOSURE, 'HTTP_METHOD_FUZZING'],
    attackParamLocations: ['QUERY', 'BODY', 'HEADER']
  })
  .threshold('MEDIUM')
  .timeout(15 * 60 * 1000)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/api/tags`
  })

  t.end()
})