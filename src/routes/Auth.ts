import express, { Request, Response } from 'express'
import passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import bcrypt from 'bcryptjs'
import { PrismaClient, user as UserModel } from '@prisma/client'

const prisma = new PrismaClient()

passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  async (email: string, password: string, done) => {
    try {
      const user: UserModel | null = await prisma.user.findUnique({ where: { email } })

      if (!user || !user.is_active) {
        return done(null, false, { message: 'Usuário não encontrado ou inativo.' })
      }

      const isValid = await bcrypt.compare(password, user.password)
      if (!isValid) {
        return done(null, false, { message: 'Senha inválida.' })
      }

      return done(null, user)
    } catch (err) {
      return done(err)
    }
  }
))

passport.serializeUser((user: Express.User, done) => {
  done(null, (user as UserModel).id)
})

passport.deserializeUser(async (id: number, done) => {
  try {
    const user: UserModel | null = await prisma.user.findUnique({ where: { id } })
    done(null, user)
  } catch (err) {
    done(err)
  }
})

export const authRouter = express.Router()

// Mock de login GET
authRouter.get('/login', (req: Request, res: Response) => {
  res.send('Formulário de login (HTML ou SPA).')
})

// POST de login
authRouter.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/oauth/authorize',
    failureRedirect: '/auth/login'
  })
)
