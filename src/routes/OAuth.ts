import express, { Request, Response } from 'express'
import oauth2orize, { OAuth2Server } from 'oauth2orize'
import * as exchange from 'oauth2orize-exchange'
import passport from 'passport'
import { generateAuthorizationCode, exchangeAuthorizationCode, exchangeRefreshToken } from '../services/OAuth.service'
import { PrismaClient, oauth_client } from '@prisma/client'

const prisma = new PrismaClient()

// Instancia o servidor OAuth2
const server: OAuth2Server = oauth2orize.createServer()

// Grant type: Authorization Code
server.grant(oauth2orize.grant.code(generateAuthorizationCode))

// Exchange: Troca código por access token
server.exchange(oauth2orize.exchange.code(exchangeAuthorizationCode))

server.exchange(oauth2orize.exchange.refreshToken(exchangeRefreshToken))

export const oauthRouter = express.Router()

// Endpoint GET /oauth/authorize
oauthRouter.get(
  '/authorize',
  passport.authenticate('local', { session: false }),
  server.authorize(async (clientID: string, redirectURI: string, done) => {
    try {
      const client: oauth_client | null = await prisma.oauth_client.findFirst({
        where: {
          client_id: clientID,
        }
      })

      if (!client) {
        return done(null, false)
      }

      const redirectURIs = JSON.parse(client.redirect_uris || '[]') as string[]

      if (!redirectURIs.includes(redirectURI)) {
        return done(null, false)
      }

      return done(null, client, redirectURI)
    } catch (err) {
      return done(err)
    }
  }),
  (req: Request, res: Response) => {
    res.send('Tela de consentimento (mock).')
  }
)

// POST /oauth/authorize/decision
oauthRouter.post(
  '/authorize/decision',
  passport.authenticate('local', { session: false }),
  server.decision()
)

// POST /oauth/token
oauthRouter.post(
  '/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler()
)
