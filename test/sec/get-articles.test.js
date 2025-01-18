'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /api/articles', async t => {
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

  // Define the security tests
  const tests = [
    TestType.EXCESSIVE_DATA_EXPOSURE,
    'id_enumeration',
    TestType.HTTP_METHOD_FUZZING,
    TestType.SQLI,
    TestType.XSS
  ]

  // Run the security tests
  await runner.createScan({
    tests,
    attackParamLocations: ['query']
  }).run({
    method: 'GET',
    url: '/api/articles',
    query: {
      tag: 'string',
      author: 'string',
      favorited: 'string',
      limit: 10,
      offset: 0
    }
  })

  t.end()
})