'use strict'
const t = require('tap')
const startServer = require('../setup-server')

// Import SecTester
const { SecRunner, TestType } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('SecTester integration for /tags route', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  // Clear SecTester runner after each test
  t.afterEach(() => runner.clear())

  // Test case for excessive data exposure
  t.test('excessive data exposure', async t => {
    await runner.createScan({
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE],
      attackParamLocations: ['QUERY', 'BODY', 'HEADER']
    }).run({
      method: 'GET',
      url: 'http://localhost:3000/tags'
    })
    t.end()
  })

  // Test case for HTTP method fuzzing
  t.test('http method fuzzing', async t => {
    await runner.createScan({
      tests: ['HTTP_METHOD_FUZZING'],
      attackParamLocations: ['QUERY', 'BODY', 'HEADER']
    }).run({
      method: 'GET',
      url: 'http://localhost:3000/tags'
    })
    t.end()
  })

  t.end()
})