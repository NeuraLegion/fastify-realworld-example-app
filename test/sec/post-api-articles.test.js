'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /api/articles', async t => {
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
    tests: [TestType.JWT, 'csrf', TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
    attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: `${server.baseUrl}/api/articles`,
    headers: {
      'Authorization': 'Token jwt.token.here',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      article: {
        title: 'string',
        description: 'string',
        body: 'string',
        tagList: ['string']
      }
    })
  })

  t.end()
})