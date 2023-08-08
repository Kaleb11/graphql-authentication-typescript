// src/graphql/schema.ts
import { gql } from 'apollo-server-express';

const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    twoFactorSecret: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type Query {
    me: User
  }
  type TwoFactorAuthResult {
    qrCodeImage: String
  }
  type Mutation {
    register(username: String!, email: String!, password: String!): AuthPayload
    login(email: String!, password: String!): AuthPayload
    changePassword(email: String!, oldPassword: String!, newPassword: String!): Boolean
    enableTwoFactorAuth(email: String!): TwoFactorAuthResult
    verifyTwoFactorAuth(email: String!, token: String!): Boolean
  }
`;

export default typeDefs;
