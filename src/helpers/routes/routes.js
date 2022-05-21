const authControllers = require("./controllers");

const authSecureRoutes = (
  expressSecured,
  validateBodyMiddleware,
  controller
) => {
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

  // create permission
  expressSecured.obPost(
    "/auth/permission",
    "OAUTH2_permission:create",
    validateBodyMiddleware({
      allowed: { type: "string" },
      applicationResource_id: { type: "number" },
    }).validate,
    controller.createPermission
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
    "/auth/user/:subjectId/role",
    "OAUTH2_user:update",
    validateBodyMiddleware({
      roles: { type: "array" },
      originalRolesList: { type: "array" },
    }).validate,
    controller.updateSubjectRoles
  );

  // client client roles
  expressSecured.obPut(
    "/auth/client/:subjectId/role",
    "OAUTH2_client:update",
    validateBodyMiddleware({
      roles: { type: "array" },
      originalRolesList: { type: "array" },
    }).validate,
    controller.updateSubjectRoles
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

  // get resources
  expressSecured.obGet(
    "/auth/resource",
    "OAUTH2_application:select",
    controller.getResources
  );

  // update role permissions
  expressSecured.obPut(
    "/auth/role/:id/permission",
    "OAUTH2_role:update",
    validateBodyMiddleware({
      newAllowedObject: { type: "object" },
      originalAllowedObject: { type: "object" },
    }).validate,
    controller.updateRolePermissions
  );

  // create a resource
  expressSecured.obPost(
    "/auth/resource",
    "OAUTH2_application:create",
    validateBodyMiddleware({
      resourceIdentifier: { type: "string" },
      applications_id: { type: "number" },
    }).validate,
    controller.createResource
  );

  // update resource permissions
  expressSecured.obPut(
    "/auth/resource/:id/permission",
    "OAUTH2_application:update",
    validateBodyMiddleware({
      newResourcePermissions: { type: "array" },
      originalResourcePermissions: { type: "array" },
    }).validate,
    controller.updateResourcePermissions
  );

  // delete resource
  expressSecured.obDelete(
    "/auth/resource/:id",
    "OAUTH2_application:delete",
    controller.deleteResource
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
  expressSecured.obPost(
    "/auth/token",
    ":",
    validateBodyMiddleware({
      grant_type: { type: "string" },
      client_id: { type: "string" },
      client_secret: { type: "string" },
    }).validate,
    controller.token
  );

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
