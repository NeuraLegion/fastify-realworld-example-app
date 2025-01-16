'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

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

t.test('GET /profiles/johndoe', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'EXCESSIVE_DATA_EXPOSURE', 'ID_ENUMERATION'],
    attackParamLocations: ['HEADER', 'QUERY', 'BODY']
  })
  .threshold('MEDIUM')
  .timeout(60000)
  .run({
    method: 'GET',
    url: '/profiles/johndoe',
    headers: { 'Authorization': 'Token optional_jwt_token' }
  })

  t.end()
})
