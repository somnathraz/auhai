const { gql } = require("apollo-server-express");

module.exports = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    role: String!
    createdAt: String!
  }

  type AuthPayload {
    accessToken: String!
    refreshToken: String
    user: User!
  }

  type RefreshResponse {
    accessToken: String!
  }

  type SignupResponse {
    message: String!
  }

  type Query {
    me: User
    listUsers: [User!]! # Admin-only query to list all users
  }

  type Mutation {
    signup(
      username: String!
      email: String!
      password: String!
    ): SignupResponse!
    login(email: String!, password: String!): AuthPayload!
    refreshToken(refreshToken: String!): RefreshResponse!
    verifyEmail(token: String!): String
    requestPasswordReset(email: String!): String
    resetPassword(token: String!, newPassword: String!): String
    updateUserRole(userId: ID!, role: String!): User! # Admin-only mutation to update a user's role
    deleteUser(userId: ID!): String! # Admin-only mutation to delete a user
  }
`;
