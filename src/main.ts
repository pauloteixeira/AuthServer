import express from 'express'
import session from 'express-session'
import bodyParser from 'body-parser'
import passport from 'passport'
import dotenv from 'dotenv'
import { oauthRouter } from './routes/OAuth'
import { authRouter } from './routes/Auth'

dotenv.config()

const app = express()

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.use(session({
  secret: process.env.SESSION_SECRET || 'oauth_secret',
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

app.use('/oauth', oauthRouter)
app.use('/auth', authRouter)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Authorization Server running at http://localhost:${PORT}`)
})
