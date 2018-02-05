import { fromEvent, FunctionEvent } from 'graphcool-lib'
import { GraphQLClient } from 'graphql-request'
import * as bcrypt from 'bcryptjs'
import * as validator from 'validator'

interface User {
  id: string
}

interface EventData {
  email: string
  password: string
  username: string
  firstName: string
  lastName: string
}

const SALT_ROUNDS = 10

export default async (event: FunctionEvent<EventData>) => {
  console.log(event)

  try {
    const graphcool = fromEvent(event)
    const api = graphcool.api('simple/v1')

    const { email, password, username, firstName, lastName } = event.data

    if (!validator.isEmail(email)) {
      return { error: 'Not a valid email' }
    }

    // check if user exists already
    const emailExists: boolean = await checkEmail(api, email)
      .then(r => r.User !== null)
    if (emailExists) {
      return { error: 'Email already in use' }
    }

    const usernameExists: boolean = await checkUsername(api, username)
      .then(r => r.User !== null)
    if (usernameExists) {
      return { error: 'Username already in use' }
    }

    // create password hash
    const salt = bcrypt.genSaltSync(SALT_ROUNDS)
    const hash = await bcrypt.hash(password, salt)

    // create new user
    const userId = await createUser(api, email, hash, username, firstName, lastName)

    // generate node token for new User node
    const token = await graphcool.generateNodeToken(userId, 'User')

    return { data: { id: userId, token } }
  } catch (e) {
    console.log(e)
    return { error: 'An unexpected error occured during signup.' }
  }
}

async function checkEmail(api: GraphQLClient, email: string): Promise<{ User }> {
  const query = `
    query getUser($email: String!) {
      User(email: $email) {
        id
      }
    }
  `

  const variables = {
    email,
  }

  return api.request<{ User }>(query, variables)
}

async function checkUsername(api: GraphQLClient, username: string): Promise<{ User }> {
  const query = `
    query getUser($username: String!) {
      User(username: $username) {
        id
      }
    }
  `

  const variables = {
    username,
  }

  return api.request<{ User }>(query, variables)
}

async function createUser(api: GraphQLClient, email: string, password: string, username: string, firstName: string, lastName: string): Promise<string> {
  const mutation = `
    mutation createUser(
      $email: String!,
      $password: String!,
      $username: String!,
      $firstName: String!,
      $lastName: String!
    ) {
      createUser(
        email: $email,
        password: $password,
        username: $username,
        firstName: $firstName,
        lastName: $lastName,
      ) {
        id
      }
    }
  `

  const variables = {
    email,
    password,
    username,
    firstName,
    lastName
  }

  return api.request<{ createUser: User }>(mutation, variables)
    .then(r => r.createUser.id)
}
