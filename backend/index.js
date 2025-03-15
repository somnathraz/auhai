const express = require("express");
const cors = require("cors");
const { ApolloServer } = require("apollo-server-express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const rateLimit = require("express-rate-limit");
const typeDefs = require("./src/graphql/typeDefs");
const resolvers = require("./src/graphql/resolvers");
const authMiddleware = require("./src/middleware/authMiddleware");
const {
  loginLimiter,
  resetPasswordLimiter,
} = require("./src/middleware/rateLimiter");

dotenv.config();

const startServer = async () => {
  const app = express();

  app.use(cors());

  // Global limiter for all requests (increase overall limit to avoid interfering with normal operations)
  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Increase overall request limit
    message: "Too many requests. Try again later.",
  });
  app.use(globalLimiter);

  // Apply authentication middleware (attaches req.userId if token is provided)
  app.use(authMiddleware);

  // Apply rate limiters only to specific operations (login and requestPasswordReset)
  app.use("/graphql", (req, res, next) => {
    // Check if the GraphQL operation is 'login'
    if (req.body && req.body.operationName === "login") {
      return loginLimiter(req, res, next);
    }
    // Check if the GraphQL operation is 'requestPasswordReset'
    if (req.body && req.body.operationName === "requestPasswordReset") {
      return resetPasswordLimiter(req, res, next);
    }
    next();
  });

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: ({ req }) => ({ req }),
  });

  await server.start();
  server.applyMiddleware({ app });

  mongoose.connect(process.env.MONGODB_URI).then(() => {
    app.listen({ port: process.env.PORT || 4000 }, () =>
      console.log(
        `🚀 Server ready at http://localhost:4000${server.graphqlPath}`
      )
    );
  });
};

startServer();
