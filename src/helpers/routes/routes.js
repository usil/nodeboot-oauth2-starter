const authControllers = require("./controllers");

const authSecureRoutes = (expressSecured, knex, validateBodyMiddleware) => {
  const controller = authControllers(knex);

  // create user
  expressSecured.obPost(
    "/auth/user",
    "OAUTH2_user:create",
    validateBodyMiddleware({
      username: { type: "string" },
      password: { type: "string" },
      roles: { type: "array" },
      name: { type: "string" },
    }),
    controller.createUser
  );
};

module.exports = authSecureRoutes;
