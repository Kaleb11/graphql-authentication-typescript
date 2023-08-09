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
    qrCodeImagePath: String
  }
  type Mutation {
    register(username: String!, email: String!, password: String!): AuthPayload
    login(email: String!, password: String!): AuthPayload
    changePassword(email: String!, oldPassword: String!, newPassword: String!): Boolean
    enableTwoFactorAuth(email: String!): TwoFactorAuthResult
    verifyTwoFactorAuth(email: String!, token: String!): Boolean
    loginWith2FA(email: String!, password: String!, code: String!): AuthPayload
  }
`;

export default typeDefs;
