'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('SecTester integration for GET /articles', async t => {
  let server
  let baseUrl

  t.before(async () => {
    server = await startServer()
    const address = server.server.address()
    baseUrl = `http://localhost:${address.port}`
  })

  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  // Placeholder for actual test cases
  t.test('security tests for GET /articles', async t => {
    await runner.createScan({
      tests: [TestType.SQLI, TestType.XSS, 'excessive_data_exposure', 'http_method_fuzzing', 'id_enumeration'],
      attackParamLocations: ['query']
    }).threshold('medium').timeout(testTimeout).run({
      method: 'GET',
      url: `${baseUrl}/articles`,
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

  t.end()
})
