declare module 'oauth2orize' {
  import { Request, Response, NextFunction } from 'express'

  export interface OAuth2Server {
    grant: (middleware: any) => void
    exchange: (middleware: any) => void
    authorize: (checkClient: Function) => any
    decision: (...args: any[]) => any
    token: () => any
    errorHandler: () => any
  }

  export function createServer(): OAuth2Server

  export namespace grant {
    function code(fn: (...args: any[]) => void): any
  }

  export namespace exchange {
    function code(fn: (...args: any[]) => void): any
  }

  export type OAuth2Client = {
    id: number
    client_id: string
    client_secret: string
    redirect_uris: string[]
  }

  export type User = {
    id: number
    email: string
  }

  export type AuthorizationCode = {
    code: string
    client_id: number
    redirect_uri: string
    user_id: number
    expires_at: Date
  }

  export type AccessToken = {
    token: string
    user_id: number
    client_id: number
    expires_at: Date
    scope: string
  }
}
