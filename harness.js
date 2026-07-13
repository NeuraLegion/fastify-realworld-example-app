'use strict'

const http = require('http')
const { URL } = require('url')
const path = require('path')
const fs = require('fs')

const PORT = Number(process.env.PORT || 3001)
const ROOT = __dirname

function sendText (res, statusCode, body) {
  res.statusCode = statusCode
  res.setHeader('content-type', 'text/plain; charset=utf-8')
  res.end(typeof body === 'string' ? body : String(body))
}

function safeJsonParse (value, fallback) {
  if (value === undefined || value === null || value === '') return fallback
  try {
    return JSON.parse(value)
  } catch (err) {
    return fallback
  }
}

function toNumberMaybe (value, fallback) {
  if (value === undefined || value === null || value === '') return fallback
  const n = Number(value)
  return Number.isNaN(n) ? value : n
}

async function readBody (req) {
  return await new Promise((resolve, reject) => {
    let data = ''
    req.on('data', chunk => {
      data += chunk
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

function loadModuleFromKnownOrDiscovered (relativePath) {
  const directPath = path.join(ROOT, relativePath)
  if (fs.existsSync(directPath)) {
    return require(directPath)
  }

  const baseName = path.basename(relativePath)
  const matches = []
  const excluded = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.cache'])

  function walk (dir) {
    let entries = []
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch (err) {
      return
    }
    for (const entry of entries) {
      if (excluded.has(entry.name)) continue
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (entry.isFile() && entry.name === baseName) {
        const normalized = full.split(path.sep).join('/')
        const wantedSuffix = relativePath.split(path.sep).join('/')
        if (normalized.endsWith(wantedSuffix)) {
          matches.push(full)
        }
      }
    }
  }

  walk(ROOT)
  if (matches.length > 0) {
    return require(matches[0])
  }
  throw new Error(`Unable to locate module for ${relativePath}`)
}

function createDecoratingStub (extra) {
  return Object.assign({
    decorate (name, value) {
      this[name] = value
    }
  }, extra || {})
}

async function createKnexBackedModels () {
  const knexFactory = loadModuleFromKnownOrDiscovered('node_modules/knex')
  const knexConfig = loadModuleFromKnownOrDiscovered('knexfile.js').development
  const knex = knexFactory(knexConfig)
  const migration = loadModuleFromKnownOrDiscovered('knex/migrations/20220919145459_create.js')
  await migration.up(knex)

  await knex('users').insert([
    { id: 1, email: 'jake@example.com', username: 'jake', image: 'http://img/jake', bio: 'bio', password: 'pw' },
    { id: 2, email: 'jane@example.com', username: 'jane', image: 'http://img/jane', bio: 'bio', password: 'pw' },
    { id: 3, email: 'alice@example.com', username: 'alice', image: 'http://img/alice', bio: 'bio', password: 'pw' }
  ])

  await knex('articles').insert([
    { id: 1, slug: 'existing-slug-xyz', title: 'Existing', description: 'desc', body: 'body', favorites_count: 0, author: 1 },
    { id: 2, slug: 'article-slug-abc', title: 'Article ABC', description: 'desc', body: 'body', favorites_count: 0, author: 2 },
    { id: 3, slug: 'my-article-slug-abc123', title: 'My Article', description: 'desc', body: 'body', favorites_count: 0, author: 1 }
  ])

  await knex('tags').insert([
    { id: 1, name: 'node' },
    { id: 2, name: 'sqlite' },
    { id: 3, name: 'dragons' }
  ])

  await knex('articles_tags').insert([
    { id: 1, article: 1, tag: 1 },
    { id: 2, article: 1, tag: 2 },
    { id: 3, article: 2, tag: 3 }
  ])

  await knex('followers').insert([
    { id: 1, user: 2, follower: 1 },
    { id: 2, user: 1, follower: 2 }
  ])

  await knex('favorites').insert([
    { id: 1, user: 2, article: 1 },
    { id: 2, user: 3, article: 1 }
  ])

  await knex('comments').insert([
    { id: 1, body: 'hello', author: 2, article: 2 },
    { id: 2, body: 'second', author: 1, article: 2 }
  ])

  return {
    knex,
    articlesModel: loadModuleFromKnownOrDiscovered('lib/models/articles.js')(knex),
    commentsModel: loadModuleFromKnownOrDiscovered('lib/models/comments.js')(knex),
    profilesModel: loadModuleFromKnownOrDiscovered('lib/models/profiles.js')(knex),
    usersModel: loadModuleFromKnownOrDiscovered('lib/models/users.js')(knex)
  }
}

async function createApiLayerTarget () {
  const plugin = loadModuleFromKnownOrDiscovered('lib/plugins/apilayer/index.js')
  const stub = createDecoratingStub()
  await plugin(stub, { apilayer: { key: 'test' } })
  if (!stub.apiLayer || typeof stub.apiLayer.post !== 'function') {
    throw new Error('apiLayer.post not available')
  }
  return stub.apiLayer
}

async function createSentimentTarget () {
  const apiLayer = await createApiLayerTarget()
  const plugin = loadModuleFromKnownOrDiscovered('lib/services/sentiment.js')
  const stub = createDecoratingStub({ apiLayer })
  await plugin(stub, {})
  if (!stub.sentimentService) {
    throw new Error('sentimentService not available')
  }
  return stub.sentimentService
}

const routes = []

function registerRoute (method, routePath, handler) {
  routes.push({ method, routePath, handler })
}

function formatResult (result) {
  if (typeof result === 'string') return result
  try {
    return JSON.stringify(result)
  } catch (err) {
    return String(result)
  }
}

function pickFirstDefined (...values) {
  for (const value of values) {
    if (value !== undefined) return value
  }
  return undefined
}

function normalizeArticleInput (body) {
  if (body && body.article && typeof body.article === 'object' && !Array.isArray(body.article)) {
    return { ...body.article }
  }
  const article = { ...body }
  delete article.userId
  delete article.userid
  delete article.slug
  return article
}

function ensureArticleDefaults (article) {
  const normalized = { ...(article || {}) }
  if (normalized.title === undefined) normalized.title = 'Harness Article'
  if (normalized.description === undefined) normalized.description = 'Created by harness'
  if (normalized.body === undefined) normalized.body = 'Harness article body'
  return normalized
}

function getArticlePayload (body) {
  if (body && body.article && typeof body.article === 'object' && !Array.isArray(body.article)) {
    return body.article
  }
  return body || {}
}

function normalizeCommentInput (body) {
  if (body && body.comment && typeof body.comment === 'object' && !Array.isArray(body.comment)) {
    return { ...body.comment }
  }
  if (body && typeof body.body === 'string') {
    return { body: body.body }
  }
  return {}
}

function ensureCommentDefaults (comment) {
  const normalized = { ...(comment || {}) }
  if (normalized.body === undefined) normalized.body = 'Harness comment body'
  return normalized
}

function normalizeUserInput (body) {
  if (body && body.user && typeof body.user === 'object' && !Array.isArray(body.user)) {
    return { ...body.user }
  }
  return { ...body }
}

function sanitizeUserInput (user) {
  const normalized = { ...(user || {}) }
  delete normalized.user
  delete normalized.userId
  delete normalized.userid
  return normalized
}

async function bootstrap () {
  registerRoute('GET', '/health', async () => 'ok')
  registerRoute('POST', '/_harness/mock-sentiment', async req => {
    const content = await readBody(req)
    const normalized = String(content || '').toLowerCase()
    let sentiment = 'neutral'
    if (/(excellent|great|good|love|well done|happy)/.test(normalized)) sentiment = 'positive'
    if (/(bad|terrible|awful|hate|sad)/.test(normalized)) sentiment = 'negative'
    return { sentiment }
  })

  try {
    const apiLayer = await createApiLayerTarget()
    registerRoute('POST', '/harness/apilayer-decorated-object-post', async req => {
      const body = safeJsonParse(await readBody(req), {})
      const url = body.url || `http://127.0.0.1:${PORT}/_harness/mock-sentiment`
      const content = pickFirstDefined(body.content, body.text, '')
      return await apiLayer.post(content, url)
    })
  } catch (err) {
    console.error('Skipping apiLayer target:', err.message)
  }

  try {
    const sentimentService = await createSentimentTarget()
    registerRoute('POST', '/harness/sentimentservice-decorated-object-getsentiment', async req => {
      const body = safeJsonParse(await readBody(req), {})
      return await sentimentService.getSentiment(body.content)
    })
    registerRoute('POST', '/harness/sentimentservice-decorated-object-getsentimentapi', async req => {
      const body = safeJsonParse(await readBody(req), {})
      return await sentimentService.getSentimentApi(body.content)
    })
    registerRoute('POST', '/harness/sentimentservice-decorated-object-splitstring', async req => {
      const body = safeJsonParse(await readBody(req), {})
      return sentimentService.splitString(body.str, toNumberMaybe(body.chunkSize, 1000))
    })
  } catch (err) {
    console.error('Skipping sentiment targets:', err.message)
  }

  try {
    const { articlesModel, commentsModel, profilesModel, usersModel } = await createKnexBackedModels()

    registerRoute('GET', '/harness/articles-model-factory-return-object-getarticles', async req => {
      const url = new URL(req.url, 'http://127.0.0.1')
      const filters = safeJsonParse(url.searchParams.get('filters'), {
        offset: toNumberMaybe(url.searchParams.get('offset'), 0),
        limit: toNumberMaybe(url.searchParams.get('limit'), 20),
        tag: url.searchParams.get('tag') || undefined,
        author: url.searchParams.get('author') || undefined,
        favorited: url.searchParams.get('favorited') || undefined
      })
      return await articlesModel.getArticles(toNumberMaybe(url.searchParams.get('userId'), url.searchParams.get('userId')), filters)
    })

    registerRoute('GET', '/harness/articles-model-factory-return-object-getarticlesfeed', async req => {
      const url = new URL(req.url, 'http://127.0.0.1')
      const filters = safeJsonParse(url.searchParams.get('filters'), {
        offset: toNumberMaybe(url.searchParams.get('offset'), 0),
        limit: toNumberMaybe(url.searchParams.get('limit'), 20)
      })
      return await articlesModel.getArticlesFeed(toNumberMaybe(url.searchParams.get('userId'), 1), filters)
    })

    registerRoute('GET', '/harness/articles-model-factory-return-object-getarticle', async req => {
      const url = new URL(req.url, 'http://127.0.0.1')
      return await articlesModel.getArticle(toNumberMaybe(url.searchParams.get('userId'), url.searchParams.get('userId')), url.searchParams.get('slug'))
    })

    registerRoute('POST', '/harness/articles-model-factory-return-object-createarticle', async req => {
      const body = safeJsonParse(await readBody(req), {})
      return await articlesModel.createArticle(toNumberMaybe(pickFirstDefined(body.userId, body.userid), 1), ensureArticleDefaults(normalizeArticleInput(body)))
    })

    registerRoute('PUT', '/harness/articles-model-factory-return-object-updatearticle', async req => {
      const body = safeJsonParse(await readBody(req), {})
      const articlePayload = getArticlePayload(body)
      return await articlesModel.updateArticle(
        toNumberMaybe(pickFirstDefined(body.userId, body.userid), 1),
        pickFirstDefined(body.slug, articlePayload.slug),
        ensureArticleDefaults(normalizeArticleInput(body))
      )
    })

    registerRoute('POST', '/harness/comments-model-factory-return-object-createcomment', async req => {
      const body = safeJsonParse(await readBody(req), {})
      return await commentsModel.createComment(
        toNumberMaybe(pickFirstDefined(body.userId, body.userid), 1),
        pickFirstDefined(body.slug, body.articleSlug),
        ensureCommentDefaults(normalizeCommentInput(body))
      )
    })

    registerRoute('GET', '/harness/comments-model-factory-return-object-getcomments', async req => {
      const url = new URL(req.url, 'http://127.0.0.1')
      return await commentsModel.getComments(toNumberMaybe(url.searchParams.get('userId'), url.searchParams.get('userId')), url.searchParams.get('slug'))
    })

    registerRoute('GET', '/harness/profiles-model-factory-return-object-getprofilebyusername', async req => {
      const url = new URL(req.url, 'http://127.0.0.1')
      return await profilesModel.getProfileByUsername(toNumberMaybe(url.searchParams.get('userId'), url.searchParams.get('userId')), url.searchParams.get('profileName'))
    })

    registerRoute('POST', '/harness/users-model-factory-return-object-registeruser', async req => {
      const body = safeJsonParse(await readBody(req), {})
      const user = normalizeUserInput(body)
      if (user.email === undefined) user.email = 'new-user@example.com'
      if (user.username === undefined) user.username = 'newuser'
      if (user.password === undefined) user.password = 'password'
      if (user.bio === undefined) user.bio = null
      if (user.image === undefined) user.image = null
      return await usersModel.registerUser(user)
    })

    registerRoute('PUT', '/harness/users-model-factory-return-object-updateuser', async req => {
      const body = safeJsonParse(await readBody(req), {})
      const user = sanitizeUserInput(normalizeUserInput(body))
      if (user.id === undefined) {
        user.id = toNumberMaybe(pickFirstDefined(body.id, body.userId, body.userid), 1)
      }
      await usersModel.updateUser(user)
      return 'updated'
    })
  } catch (err) {
    console.error('Skipping database-backed targets:', err.message)
  }

  const server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname
    const route = routes.find(r => r.method === req.method && r.routePath === pathname)
    if (!route) {
      sendText(res, 404, 'not found')
      return
    }
    try {
      const result = await route.handler(req, res)
      sendText(res, 200, formatResult(result))
    } catch (err) {
      sendText(res, 500, err && err.stack ? err.stack : String(err))
    }
  })

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Harness listening on ${PORT}`)
  })
}

bootstrap().catch(err => {
  console.error(err)
  process.exit(1)
})
