const authControllers = require("./controllers");

const authSecureRoutes = (
  expressSecured,
  knex,
  validateBodyMiddleware,
  jwtSecret,
  jwtExpirationTime = "24h",
  cryptoSecret = "key"
) => {
  const controller = authControllers(
    knex,
    jwtSecret,
    jwtExpirationTime,
    cryptoSecret
  );

  // create user
  expressSecured.obPost(
    "/auth/user",
    "OAUTH2_user:create",
    validateBodyMiddleware({
      username: { type: "string" },
      password: { type: "string" },
      description: { type: "string" },
      roles: { type: "array" },
      name: { type: "string" },
    }).validate,
    controller.createUser
  );

  // create client
  expressSecured.obPost(
    "/auth/client",
    "OAUTH2_client:create",
    validateBodyMiddleware({
      identifier: { type: "string" },
      description: { type: "string" },
      roles: { type: "array" },
      name: { type: "string" },
    }).validate,
    controller.createClient
  );

  // create role
  expressSecured.obPost(
    "/auth/role",
    "OAUTH2_role:create",
    validateBodyMiddleware({
      identifier: { type: "string" },
      allowedObject: { type: "object" },
    }).validate,
    controller.createRole
  );

  // create application
  expressSecured.obPost(
    "/auth/application",
    "OAUTH2_application:create",
    validateBodyMiddleware({
      identifier: { type: "string" },
    }).validate,
    controller.createApplication
  );

  // create option
  expressSecured.obPost(
    "/auth/option",
    "OAUTH2_option:create",
    validateBodyMiddleware({
      allowed: { type: "string" },
      applicationPart_id: { type: "number" },
    }).validate,
    controller.createOption
  );

  // get users
  expressSecured.obGet("/auth/user", "OAUTH2_user:select", controller.getUsers);

  // get user
  expressSecured.obGet(
    "/auth/user/:id",
    "OAUTH2_user:select",
    controller.getUser
  );

  // get user profile
  expressSecured.obGet("/auth/user/profile/me", ":", controller.getMe);

  // get clients
  expressSecured.obGet(
    "/auth/client",
    "OAUTH2_client:select",
    controller.getClients
  );

  // update user roles
  expressSecured.obPut(
    "/auth/user/:id/role",
    "OAUTH2_user:update",
    validateBodyMiddleware({
      roles: { type: "array" },
    }).validate,
    controller.updateUserRoles
  );

  // client user roles
  expressSecured.obPut(
    "/auth/client/:id/role",
    "OAUTH2_client:update",
    validateBodyMiddleware({
      roles: { type: "array" },
    }).validate,
    controller.updateClientRoles
  );

  // delete user
  expressSecured.obDelete(
    "/auth/user/:subjectId",
    "OAUTH2_user:delete",
    controller.deleteUser
  );

  // delete client
  expressSecured.obDelete(
    "/auth/client/:subjectId",
    "OAUTH2_client:delete",
    controller.deleteClient
  );

  // delete role
  expressSecured.obDelete(
    "/auth/role/:id",
    "OAUTH2_role:delete",
    controller.deleteRole
  );

  // update user
  expressSecured.obPut(
    "/auth/user/:subjectId",
    "OAUTH2_user:update",
    validateBodyMiddleware({
      name: { type: "string" },
    }).validate,
    controller.updateUser
  );

  // update password
  expressSecured.obPut(
    "/auth/user/:id/password",
    "OAUTH2_user:update",
    validateBodyMiddleware({
      newPassword: { type: "string" },
      oldPassword: { type: "string" },
    }).validate,
    controller.updatePassword
  );

  // update client
  expressSecured.obPut(
    "/auth/client/:subjectId",
    "OAUTH2_client:update",
    validateBodyMiddleware({
      name: { type: "string" },
    }).validate,
    controller.updateClient
  );

  // get roles
  expressSecured.obGet("/auth/role", "OAUTH2_role:select", controller.getRoles);

  // get parts
  expressSecured.obGet(
    "/auth/part",
    "OAUTH2_application:select",
    controller.getParts
  );

  // update role options
  expressSecured.obPut(
    "/auth/role/:id/option",
    "OAUTH2_role:update",
    validateBodyMiddleware({
      newAllowedObject: { type: "object" },
      originalAllowedObject: { type: "object" },
    }).validate,
    controller.updateRoleOptions
  );

  // create a part
  expressSecured.obPost(
    "/auth/part",
    "OAUTH2_application:create",
    validateBodyMiddleware({
      partIdentifier: { type: "string" },
      applications_id: { type: "number" },
    }).validate,
    controller.createPart
  );

  // update part options
  expressSecured.obPut(
    "/auth/part/:id/option",
    "OAUTH2_application:update",
    validateBodyMiddleware({
      newPartOptions: { type: "array" },
      originalPartOptions: { type: "array" },
    }).validate,
    controller.updatePartOptions
  );

  // delete part
  expressSecured.obDelete(
    "/auth/part/:id",
    "OAUTH2_application:delete",
    controller.deletePart
  );

  // get applications
  expressSecured.obGet(
    "/auth/application",
    "OAUTH2_application:select",
    controller.selectApplications
  );

  expressSecured.obPost(
    "/auth/login",
    ":",
    validateBodyMiddleware({
      username: { type: "string" },
      password: { type: "string" },
    }).validate,
    controller.login
  );

  // Gets a token
  expressSecured.obPost("/auth/token", ":", controller.token);

  // Revoke tokens
  expressSecured.obPut(
    "/auth/client/:id/revoke",
    "OAUTH2_client:update",
    controller.revokeToken
  );

  // Generate long live
  expressSecured.obPut(
    "/auth/client/:id/long-live",
    "OAUTH2_client:update",
    validateBodyMiddleware({
      identifier: { type: "string" },
    }).validate,
    controller.generateLongLive
  );

  // The admin gets the client secret
  expressSecured.obGet(
    "/auth/client/:id/secret",
    "OAUTH2_client:select",
    controller.getClientSecret
  );
};

module.exports = authSecureRoutes;
