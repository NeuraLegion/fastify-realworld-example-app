import { ArticlesModule } from '../../src/articles';
import config from '../../src/mikro-orm.config';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { MikroOrmModule } from '@mikro-orm/nestjs';
import { Server } from 'https';

describe('/articles', () => {
  const timeout = 600000;
  jest.setTimeout(timeout);

  let runner!: SecRunner;
  let app!: INestApplication;
  let baseUrl!: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ArticlesModule,
        ConfigModule.forRoot(),
        MikroOrmModule.forRoot(config)
      ]
    }).compile();

    app = moduleFixture.createNestApplication({
      logger: false
    });
    await app.init();

    const server = app.getHttpServer();

    server.listen(0);

    const port = server.address().port;
    const protocol = server instanceof Server ? 'https' : 'http';
    baseUrl = `${protocol}://localhost:${port}`;
  });

  afterAll(() => app.close());

  beforeEach(async () => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME! });

    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: `${baseUrl}/articles`,
          query: {
            tag: 'test',
            author: 'test',
            favorited: 'test',
            limit: 10,
            offset: 0
          }
        });
    });
  });

  describe('GET /:slug', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.PATH]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: `${baseUrl}/articles/test-article`
        });
    });
  });

  describe('POST /articles/{slug}/favorite', () => {
    it('should not have XSS', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: `${baseUrl}/articles/test-article/favorite`,
          headers: { Authorization: 'Token jwt.token.here' },
          body: {}
        });
    });
  });
});