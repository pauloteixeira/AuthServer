import { Request } from 'express'
import { User, OAuth2Client, AuthorizationCode, AccessToken } from 'oauth2orize'
import { PrismaClient, authorization_code, access_token, refresh_token } from '@prisma/client'
import { v4 as uuidv4 } from 'uuid'
import crypto from 'crypto'

const prisma = new PrismaClient()

// Gera um código de autorização e salva no banco
export async function generateAuthorizationCode(
  client: OAuth2Client,
  redirectUri: string,
  user: User,
  _aRes: any,
  done: (err: Error | null, code?: string) => void
): Promise<void> {
  try {
    const code = uuidv4()
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000) // 10 minutos

    await prisma.authorization_code.create({
      data: {
        code,
        client_id: (client as any).id,
        user_id: (user as any).id,
        redirect_uri: redirectUri,
        expires_at: expiresAt,
      }
    })

    done(null, code)
  } catch (err) {
    done(err as Error)
  }
}

// Troca o código por um access token
export async function exchangeAuthorizationCode(
  client: OAuth2Client,
  code: string,
  redirectUri: string,
  done: (err: Error | null, accessToken?: string, refreshToken?: string, params?: any) => void
): Promise<void> {
  try {
    const authCode: authorization_code | null = await prisma.authorization_code.findUnique({
      where: { code }
    })

    if (
      !authCode ||
      authCode.client_id !== (client as any).id ||
      authCode.redirect_uri !== redirectUri ||
      new Date() > authCode.expires_at
    ) {
      return done(null, false)
    }

    // Geração dos tokens
    const accessToken = crypto.randomBytes(32).toString('hex')
    const refreshToken = crypto.randomBytes(32).toString('hex')
    const accessExpiresAt = new Date(Date.now() + 3600 * 1000) // 1 hora
    const refreshExpiresAt = new Date(Date.now() + 86400 * 1000) // 24h

    await prisma.access_token.create({
      data: {
        token: accessToken,
        client_id: authCode.client_id,
        user_id: authCode.user_id,
        scope: 'default',
        expires_at: accessExpiresAt,
      }
    })

    await prisma.refresh_token.create({
      data: {
        token: refreshToken,
        client_id: authCode.client_id,
        user_id: authCode.user_id,
        scope: 'default',
        expires_at: refreshExpiresAt,
      }
    })

    // Opcional: apagar código de autorização
    await prisma.authorization_code.delete({ where: { code } })

    done(null, accessToken, refreshToken, { token_type: 'Bearer', expires_in: 3600 })
  } catch (err) {
    done(err as Error)
  }
}
