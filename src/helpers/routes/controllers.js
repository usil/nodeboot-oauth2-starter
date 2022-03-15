const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const generalHelpers = require("../general-helpers.js");
const randomstring = require("randomstring");
const crypto = require("crypto");

const authControllers = (
  knex,
  jwtSecret,
  expiresIn = "24h",
  cryptoSecret = "key",
  clientIdSuffix = "::client.app"
) => {
  const controller = {};

  controller.createUser = async (req, res) => {
    try {
      const { password } = req.body;
      const encryptedPassword = await bcrypt.hash(password, 10);

      req.body.encryptedPassword = encryptedPassword;

      let userId = -1;

      await knex.transaction(async (trx) => {
        userId = await controller.createUserTransaction(trx, req.body);
      });

      return res
        .status(201)
        .json({ code: 200001, message: "User added", content: { userId } });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createUserTransaction = async (trx, reqBody) => {
    try {
      const { username, name, roles, encryptedPassword, description } = reqBody;

      const firstResult = await trx.table("OAUTH2_Subjects").insert({
        name,
        description,
      });

      const userId = await trx.table("OAUTH2_Users").insert({
        username: username.toLowerCase(),
        password: encryptedPassword,
        subject_id: firstResult[0],
      });

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: firstResult[0], roles_id: r.id };
      });

      await trx.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);

      return userId[0];
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.createClientTransaction = async (
    trx,
    reqBody,
    longLive = false
  ) => {
    try {
      const { identifier, name, roles, description } = reqBody;

      const clientSecret = randomstring.generate();
      let clientStringId = randomstring.generate(20);

      clientStringId += clientIdSuffix;

      const algorithm = "aes-256-ctr";
      const initVector = crypto.randomBytes(16);
      const key = crypto.scryptSync(cryptoSecret, "salt", 32);
      const cipher = crypto.createCipheriv(algorithm, key, initVector);
      let encryptedData = cipher.update(clientSecret, "utf-8", "hex");
      encryptedData += cipher.final("hex");

      const firstResult = await trx.table("OAUTH2_Subjects").insert({
        name,
        description,
      });

      const hexedInitVector = initVector.toString("hex");

      const result = await trx.table("OAUTH2_Clients").insert({
        identifier: identifier.toLowerCase(),
        client_id: clientStringId,
        client_secret: hexedInitVector + "|.|" + encryptedData,
        subject_id: firstResult[0],
      });

      let access_token = "";

      if (longLive === true || longLive === "true") {
        access_token = jwt.sign(
          {
            data: {
              id: result[0],
              subjectType: "client",
              identifier: identifier.toLowerCase(),
            },
          },
          jwtSecret
        );

        const encryptedAccessToken = await bcrypt.hash(access_token, 10);

        await trx
          .table("OAUTH2_Clients")
          .update({
            access_token: encryptedAccessToken,
          })
          .where("OAUTH2_Clients.id", "=", result[0]);
      }

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: firstResult[0], roles_id: r.id };
      });

      await trx.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);

      return { clientSecret, clientId: clientStringId, access_token };
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  };

  controller.createClient = async (req, res) => {
    try {
      let response;

      const { longLive } = req.query;

      await knex.transaction(async (trx) => {
        response = await controller.createClientTransaction(
          trx,
          req.body,
          longLive
        );
      });

      return res.status(201).json({
        code: 200001,
        message: "Client added",
        content: response,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createRole = async (req, res) => {
    try {
      let roleId;

      await knex.transaction(async (trx) => {
        roleId = await controller.createRoleTransaction(trx, req.body);
      });
      return res
        .status(201)
        .json({ code: 200001, message: "Role added", content: { roleId } });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createRoleTransaction = async (trx, reqBody) => {
    try {
      const { identifier, allowedObject } = reqBody;
      const insertResult = await trx.table("OAUTH2_Roles").insert({
        identifier: identifier.toLowerCase(),
      });
      const insertRolePermissions = [];
      for (const allowed in allowedObject) {
        for (const a of allowedObject[allowed]) {
          insertRolePermissions.push({
            roles_id: insertResult[0],
            permissions_id: a.id,
          });
        }
      }
      await trx.table("OAUTH2_RolePermission").insert(insertRolePermissions);

      return insertResult[0];
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.createApplication = async (req, res) => {
    try {
      const { identifier } = req.body;
      const applicationId = await knex
        .table("OAUTH2_Applications")
        .insert({ identifier });
      return res.status(201).json({
        code: 200001,
        message: "Application added",
        content: { applicationId: applicationId[0] },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createApplicationResource = async (req, res) => {
    try {
      const { resourceIdentifier, applications_id } = req.body;
      const applicationResourceId = await knex
        .table("OAUTH2_ApplicationResource")
        .insert({
          resourceIdentifier: resourceIdentifier,
          applications_id,
        });
      return res.status(201).json({
        code: 200001,
        message: "Application resource added",
        content: applicationResourceId[0],
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createPermission = async (req, res) => {
    try {
      const { allowed, applicationResource_id } = req.body;
      const permissionId = await knex.table("OAUTH2_Permissions").insert({
        allowed,
        applicationResource_id,
      });
      return res.status(201).json({
        code: 200001,
        message: "Permission added",
        content: { permissionId: permissionId[0] },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getUsers = async (req, res) => {
    try {
      let itemsPerPage = 5;
      let pageIndex = 0;
      let order = "desc";

      if (
        req.query["itemsPerPage"] &&
        parseInt(req.query["itemsPerPage"]) >= 1
      ) {
        itemsPerPage = parseInt(req.query["itemsPerPage"]);
      }

      if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
        pageIndex = parseInt(req.query["pageIndex"]);
      }

      if (
        req.query["order"] &&
        (req.query["order"] === "desc" || req.query["order"] === "asc")
      ) {
        order = req.query["order"];
      }

      const offset = itemsPerPage * pageIndex;

      const userTotalCount = (
        await knex("OAUTH2_Users").where("OAUTH2_Users.deleted", false).count()
      )[0]["count(*)"];

      const totalPages = Math.ceil(userTotalCount / itemsPerPage);

      const users = await knex({
        OAUTH2_Users: knex("OAUTH2_Users")
          .limit(itemsPerPage)
          .offset(offset)
          .orderBy("id", order),
      })
        .select(
          "OAUTH2_Users.id",
          "OAUTH2_Users.username",
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.description",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Roles.id as roleId",
          "OAUTH2_Roles.identifier as roleIdentifier"
        )
        .join(
          "OAUTH2_Subjects",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
        .join(
          "OAUTH2_RolePermission",
          `OAUTH2_RolePermission.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.id`,
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          `OAUTH2_ApplicationResource.id`,
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where("OAUTH2_Users.deleted", false);

      const helper = generalHelpers();

      const parsedUsers = helper.parseSubjectSearch(users, "user");

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: {
          items: parsedUsers,
          pageIndex,
          itemsPerPage,
          totalItems: userTotalCount,
          totalPages,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getUser = async (req, res) => {
    try {
      if (isNaN(req.params.id)) {
        return res.status(400).json({
          code: 400000,
          message: "Invalid user id",
        });
      }
      const users = await knex
        .table("OAUTH2_Users")
        .select(
          "OAUTH2_Users.id",
          "OAUTH2_Users.username",
          "OAUTH2_Subjects.description",
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Roles.id as roleId",
          "OAUTH2_Roles.identifier as roleIdentifier"
        )
        .join(
          "OAUTH2_Subjects",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
        .join(
          "OAUTH2_RolePermission",
          `OAUTH2_RolePermission.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.id`,
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          `OAUTH2_ApplicationResource.id`,
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where("OAUTH2_Users.id", req.params.id);

      const helper = generalHelpers();
      const parsedUsers = helper.parseSubjectSearch(users, "user");

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: parsedUsers,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getMe = async (req, res) => {
    try {
      if (!res.locals.user) {
        return res.status(403).json({
          code: 400301,
          message: "Forbidden user",
        });
      }
      if (res.locals.user && res.locals.user.subjectType !== "user") {
        return res.status(400).json({
          code: 400001,
          message: "Invalid subject user",
        });
      }

      const users = await knex
        .table("OAUTH2_Users")
        .select(
          "OAUTH2_Users.id",
          "OAUTH2_Users.username",
          "OAUTH2_Subjects.description",
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Roles.id as roleId",
          "OAUTH2_Roles.deleted as roleDeleted",
          "OAUTH2_Roles.identifier as roleIdentifier"
        )
        .join(
          "OAUTH2_Subjects",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          `OAUTH2_Users.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
        .join(
          "OAUTH2_RolePermission",
          `OAUTH2_RolePermission.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.id`,
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          `OAUTH2_ApplicationResource.id`,
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where("OAUTH2_Users.username", res.locals.user.username);

      const helper = generalHelpers();
      const parsedUsers = helper.parseSubjectSearch(users, "user");

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: parsedUsers[0],
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getClients = async (req, res) => {
    try {
      let itemsPerPage = 5;
      let pageIndex = 0;
      let order = "desc";

      if (
        req.query["itemsPerPage"] &&
        parseInt(req.query["itemsPerPage"]) >= 1
      ) {
        itemsPerPage = parseInt(req.query["itemsPerPage"]);
      }

      if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
        pageIndex = parseInt(req.query["pageIndex"]);
      }

      if (
        req.query["order"] &&
        (req.query["order"] === "desc" || req.query["order"] === "asc")
      ) {
        order = req.query["order"];
      }

      const offset = itemsPerPage * pageIndex;

      const userTotalCount = (
        await knex("OAUTH2_Clients")
          .where("OAUTH2_Clients.deleted", false)
          .count()
      )[0]["count(*)"];

      const totalPages = Math.ceil(userTotalCount / itemsPerPage);

      const clients = await knex({
        OAUTH2_Clients: knex("OAUTH2_Clients")
          .limit(itemsPerPage)
          .offset(offset)
          .orderBy("id", order),
      })
        .select(
          "OAUTH2_Clients.id",
          "OAUTH2_Clients.client_id",
          "OAUTH2_Clients.revoked",
          "OAUTH2_Clients.access_token",
          "OAUTH2_Clients.identifier",
          "OAUTH2_Subjects.description",
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Roles.id as roleId",
          "OAUTH2_Roles.deleted as roleDeleted",
          "OAUTH2_Roles.identifier as roleIdentifier"
        )
        .join(
          "OAUTH2_Subjects",
          `OAUTH2_Clients.subject_id`,
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          `OAUTH2_Clients.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
        .join(
          "OAUTH2_RolePermission",
          `OAUTH2_RolePermission.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.id`,
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          `OAUTH2_ApplicationResource.id`,
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where("OAUTH2_Clients.deleted", false);

      const helper = generalHelpers();
      const parsedUsers = helper.parseSubjectSearch(clients, "client");

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: {
          items: parsedUsers,
          pageIndex,
          itemsPerPage,
          totalItems: userTotalCount,
          totalPages,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateUserRoles = async (req, res) => {
    try {
      const { roles } = req.body;

      const userId = req.params.id;

      if (userId && isNaN(userId)) {
        return res.status(400).json({
          code: 400000,
          message: "User id is not valid",
        });
      }

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: userId, roles_id: r.id };
      });

      await knex.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);

      return res
        .status(201)
        .json({ code: 200000, message: "User roles added" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateClientRoles = async (req, res) => {
    try {
      const { roles } = req.body;
      const clientId = req.params.id;

      if (clientId && isNaN(clientId)) {
        return res.status(400).json({
          code: 400000,
          message: "User id is not valid",
        });
      }

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: clientId, roles_id: r.id };
      });

      await knex.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);

      return res
        .status(201)
        .json({ code: 200000, message: "Client roles added" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.deleteUserTransaction = async (trx, subjectId) => {
    try {
      await trx
        .table("OAUTH2_Users")
        .where({ subject_id: subjectId })
        .update("deleted", true);

      await trx
        .table("OAUTH2_Subjects")
        .where({ id: subjectId })
        .update("deleted", true);
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.deleteUser = async (req, res) => {
    try {
      const subjectId = req.params.subjectId;

      await knex.transaction(async (trx) => {
        await controller.deleteUserTransaction(trx, subjectId);
      });

      return res.status(201).json({ code: 200001, message: "User deleted" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.deleteClientTransaction = async (trx, subjectId) => {
    try {
      await trx
        .table("OAUTH2_Clients")
        .where({ subject_id: subjectId })
        .update("deleted", true);

      await trx
        .table("OAUTH2_Subjects")
        .where({ id: subjectId })
        .update("deleted", true);
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.deleteClient = async (req, res) => {
    try {
      const subjectId = req.params.subjectId;

      await knex.transaction(async (trx) => {
        await controller.deleteClientTransaction(trx, subjectId);
      });

      return res.status(201).json({ code: 200001, message: "Client deleted" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.deleteRole = async (req, res) => {
    try {
      const roleId = req.params.id;

      await knex
        .table("OAUTH2_Roles")
        .where({ id: roleId })
        .update("deleted", true);

      return res.status(201).json({ code: 200001, message: "Role deleted" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateUser = async (req, res) => {
    try {
      const { name } = req.body;
      const subjectId = req.params.subjectId;

      if (subjectId && isNaN(subjectId)) {
        return res.status(400).json({
          code: 400001,
          message: "Subject id is invalid",
        });
      }

      await knex
        .table("OAUTH2_Subjects")
        .where({ id: subjectId })
        .update({ name });

      return res.status(201).json({ code: 200001, message: "User updated" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updatePassword = async (req, res) => {
    try {
      const { newPassword, oldPassword } = req.body;

      const user = await knex
        .table("OAUTH2_Users")
        .select()
        .where({ id: req.params.id });

      const correctPassword = await bcrypt.compare(
        oldPassword,
        user[0].password
      );

      if (!correctPassword) {
        return res.status(400).json({
          code: 400001,
          message: "Incorrect password",
        });
      }

      const encryptedPassword = await bcrypt.hash(newPassword, 10);

      await knex
        .table("OAUTH2_Users")
        .update({ password: encryptedPassword })
        .where({ id: req.params.id });

      return res
        .status(201)
        .json({ code: 200000, message: "User password updated" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateClient = async (req, res) => {
    try {
      const { name } = req.body;
      const subjectId = req.params.subjectId;

      await knex
        .table("OAUTH2_Subjects")
        .where({ id: subjectId })
        .update({ name });

      return res.status(201).json({ code: 200000, message: "Client updated" });
    } catch (error) {
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getRoles = async (req, res) => {
    try {
      const basic = req.query["basic"];
      if (basic && basic == "true") {
        const roles = await knex
          .table("OAUTH2_Roles")
          .select("OAUTH2_Roles.id", "OAUTH2_Roles.identifier")
          .where({ deleted: false });
        return res.status(200).json({
          code: 200000,
          message: "Select completed",
          content: roles,
        });
      }
      let itemsPerPage = 5;
      let pageIndex = 0;
      let order = "desc";

      if (
        req.query["itemsPerPage"] &&
        parseInt(req.query["itemsPerPage"]) >= 1
      ) {
        itemsPerPage = parseInt(req.query["itemsPerPage"]);
      }

      if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
        pageIndex = parseInt(req.query["pageIndex"]);
      }

      if (
        req.query["order"] &&
        (req.query["order"] === "desc" || req.query["order"] === "asc")
      ) {
        order = req.query["order"];
      }

      const offset = itemsPerPage * pageIndex;

      const rolesTotalCount = (
        await knex("OAUTH2_Roles").where("OAUTH2_Roles.deleted", false).count()
      )[0]["count(*)"];

      const totalPages = Math.ceil(rolesTotalCount / itemsPerPage);

      const roles = await knex({
        OAUTH2_Roles: knex("OAUTH2_Roles")
          .limit(itemsPerPage)
          .offset(offset)
          .orderBy("OAUTH2_Roles.id", order),
      })
        .select(
          "OAUTH2_Roles.id",
          "OAUTH2_Roles.identifier",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Permissions.id as permissionId"
        )
        .join(
          "OAUTH2_RolePermission",
          `OAUTH2_RolePermission.roles_id`,
          "OAUTH2_Roles.id"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.id`,
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          `OAUTH2_ApplicationResource.id`,
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where("OAUTH2_Roles.deleted", false);

      const helpers = generalHelpers();
      const parsedRoles = helpers.parseRoleSearch(roles);

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: {
          items: parsedRoles,
          pageIndex,
          itemsPerPage,
          totalItems: rolesTotalCount,
          totalPages,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getResources = async (req, res) => {
    try {
      if (req.query["basic"] && req.query["basic"] == "true") {
        const resourceSelectBasicQuery = knex
          .table("OAUTH2_ApplicationResource")
          .select(
            "OAUTH2_ApplicationResource.resourceIdentifier as applicationResourceName",
            "OAUTH2_ApplicationResource.id as resourceId",
            "OAUTH2_Permissions.allowed",
            "OAUTH2_Permissions.id as permissionId"
          )
          .join(
            "OAUTH2_Permissions",
            `OAUTH2_Permissions.applicationResource_id`,
            "OAUTH2_ApplicationResource.id"
          )
          .where("OAUTH2_ApplicationResource.deleted", false)
          .where("OAUTH2_Permissions.deleted", false);

        const resourcesBasicResult = await resourceSelectBasicQuery;

        const helpers = generalHelpers();

        const parsedResources =
          helpers.parseResourceSearch(resourcesBasicResult);

        return res.status(200).json({
          code: 200000,
          message: "Select completed",
          content: parsedResources,
        });
      }

      let itemsPerPage = 5;
      let pageIndex = 0;
      let order = "desc";

      if (
        req.query["itemsPerPage"] &&
        parseInt(req.query["itemsPerPage"]) >= 1
      ) {
        itemsPerPage = parseInt(req.query["itemsPerPage"]);
      }

      if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
        pageIndex = parseInt(req.query["pageIndex"]);
      }

      if (
        req.query["order"] &&
        (req.query["order"] === "desc" || req.query["order"] === "asc")
      ) {
        order = req.query["order"];
      }

      const offset = itemsPerPage * pageIndex;

      const resourcesTotalCount = (
        await knex("OAUTH2_ApplicationResource")
          .where("OAUTH2_ApplicationResource.deleted", false)
          .count()
      )[0]["count(*)"];

      const totalPages = Math.ceil(resourcesTotalCount / itemsPerPage);

      const resourcesFullResult = await knex({
        OAUTH2_ApplicationResource: knex("OAUTH2_ApplicationResource")
          .limit(itemsPerPage)
          .offset(offset)
          .orderBy("OAUTH2_ApplicationResource.id", order),
      })
        .select(
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResourceName",
          "OAUTH2_ApplicationResource.id as resourceId",
          "OAUTH2_Permissions.allowed",
          "OAUTH2_Permissions.id as permissionId"
        )
        .join(
          "OAUTH2_Permissions",
          `OAUTH2_Permissions.applicationResource_id`,
          "OAUTH2_ApplicationResource.id"
        )
        .where("OAUTH2_ApplicationResource.deleted", false)
        .where("OAUTH2_Permissions.deleted", false)
        .orderBy("OAUTH2_ApplicationResource.id", "asc");

      const helpers = generalHelpers();
      console.log(resourcesFullResult);
      const parsedResources = helpers.parseResourceSearch(resourcesFullResult);

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: {
          items: parsedResources,
          pageIndex,
          itemsPerPage,
          totalItems: resourcesTotalCount,
          totalPages,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateRolePermissionsTransaction = async (
    trx,
    roleId,
    reqBody
  ) => {
    try {
      const { newAllowedObject, originalAllowedObject } = reqBody;

      const newAllowedArray = [];
      const originalAllowedArray = [];
      const rolePermissionToInsert = [];

      for (const allowed in newAllowedObject) {
        for (const a of newAllowedObject[allowed]) {
          newAllowedArray.push({
            roles_id: roleId,
            permissions_id: a.id,
          });
        }
      }

      for (const allowed in originalAllowedObject) {
        for (const a of originalAllowedObject[allowed]) {
          originalAllowedArray.push({
            roles_id: roleId,
            permissions_id: a.id,
          });
        }
      }

      for (const allowed of newAllowedArray) {
        const indexOfRolePermission = originalAllowedArray.findIndex(
          (orp) => orp.permissions_id === allowed.permissions_id
        );
        if (indexOfRolePermission === -1) {
          rolePermissionToInsert.push(allowed);
        }
      }

      for (const allowed of originalAllowedArray) {
        const indexOfRolePermission = newAllowedArray.findIndex(
          (orp) => orp.permissions_id === allowed.permissions_id
        );
        if (indexOfRolePermission === -1) {
          await trx
            .table("OAUTH2_RolePermission")
            .where({
              roles_id: allowed.roles_id,
              permissions_id: allowed.permissions_id,
            })
            .del();
        }
      }

      if (rolePermissionToInsert.length !== 0) {
        await trx.table("OAUTH2_RolePermission").insert(rolePermissionToInsert);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.updateRolePermissions = async (req, res) => {
    try {
      const roleId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.updateRolePermissionsTransaction(
          trx,
          roleId,
          req.body
        );
      });

      return res.status(201).json({
        code: 200001,
        message: "Role permissions updated",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updateResourcePermissionsTransaction = async (
    trx,
    resourceId,
    reqBody
  ) => {
    try {
      const { newResourcePermissions, originalResourcePermissions } = reqBody;

      const permissionsToInsert = [];

      for (const permissions of newResourcePermissions) {
        const indexOnOriginal = originalResourcePermissions.findIndex(
          (opt) => opt.allowed.toLowerCase() === permissions.allowed
        );
        if (indexOnOriginal === -1) {
          permissionsToInsert.push({
            allowed: permissions.allowed.toLowerCase(),
            applicationResource_id: resourceId,
          });
        }
      }

      for (const permission of originalResourcePermissions) {
        const indexOnNew = newResourcePermissions.findIndex(
          (opt) => opt.allowed.toLowerCase() === permission.allowed
        );
        if (indexOnNew === -1) {
          await trx
            .table("OAUTH2_Permissions")
            .update({ deleted: true })
            .where({
              allowed: permission.allowed,
              applicationResource_id: resourceId,
            });
        }
      }

      if (permissionsToInsert.length !== 0) {
        await trx.table("OAUTH2_Permissions").insert(permissionsToInsert);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.updateResourcePermissions = async (req, res) => {
    try {
      const resourceId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.updateResourcePermissionsTransaction(
          trx,
          resourceId,
          req.body
        );
      });

      return res.status(201).json({
        code: 200001,
        message: "Resource permissions updated",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createResource = async (req, res) => {
    try {
      const { resourceIdentifier, applications_id } = req.body;

      const insertResult = await knex
        .table("OAUTH2_ApplicationResource")
        .insert({
          resourceIdentifier,
          applications_id,
        });

      const permissionsToInsert = [
        { allowed: "*", applicationResource_id: insertResult[0] },
        { allowed: "create", applicationResource_id: insertResult[0] },
        { allowed: "update", applicationResource_id: insertResult[0] },
        { allowed: "delete", applicationResource_id: insertResult[0] },
        { allowed: "select", applicationResource_id: insertResult[0] },
      ];

      await knex.table("OAUTH2_Permissions").insert(permissionsToInsert);

      return res.status(201).json({
        code: 200001,
        message: "Application resource added",
        content: {
          applicationResourceId: insertResult[0],
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.deleteResourceTransaction = async (trx, resourceId) => {
    try {
      await trx
        .table("OAUTH2_ApplicationResource")
        .update({ deleted: true })
        .where({ id: resourceId });

      await trx
        .table("OAUTH2_Permissions")
        .update({ deleted: true })
        .where({ applicationResource_id: resourceId });
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.deleteResource = async (req, res) => {
    try {
      const resourceId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.deleteResourceTransaction(trx, resourceId);
      });

      return res.status(201).json({
        code: 200001,
        message: "Resource deleted",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.selectApplications = async (req, res) => {
    try {
      const applications = await knex
        .table("OAUTH2_Applications")
        .select("id", "identifier")
        .where({ deleted: false });

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: applications,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.login = async (req, res) => {
    try {
      const { username, password } = req.body;

      const preUser = await knex
        .table("OAUTH2_Users")
        .select(
          "OAUTH2_Subjects.name",
          "OAUTH2_Users.*",
          "OAUTH2_Roles.identifier as roles"
        )
        .join(
          "OAUTH2_Subjects",
          "OAUTH2_Users.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          "OAUTH2_SubjectRole.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join("OAUTH2_Roles", "OAUTH2_Roles.id", "OAUTH2_SubjectRole.roles_id")
        .where("OAUTH2_Users.username", username.toLowerCase());

      const helpers = generalHelpers();
      const parsedUser = helpers.joinSearch(preUser, "id", "roles");

      const correctPassword = await bcrypt.compare(
        password,
        parsedUser[0].password
      );

      if (!correctPassword) {
        return res.status(401).json({
          code: 400001,
          message: "Incorrect password",
        });
      }
      const token = jwt.sign(
        {
          data: {
            id: parsedUser[0].id,
            subjectType: "user",
            username: preUser[0].username,
          },
        },
        jwtSecret,
        {
          expiresIn: expiresIn,
        }
      );
      return res.status(201).json({
        message: `User ${username} logged in`,
        code: 200000,
        content: {
          jwt_token: token,
          username,
          name: parsedUser[0].name,
          userId: parsedUser[0].id,
          roles: parsedUser[0].roles,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.token = async (req, res) => {
    try {
      const grant_type = req.body.grant_type;

      if (grant_type !== "client_credentials" && grant_type !== "password") {
        return res.status(400).json({
          code: 400400,
          message: "Unsupported grand type",
        });
      }

      if (grant_type === "client_credentials") {
        const { client_id, client_secret } = req.body;
        const [clientResponse, error] = await controller.handleClientToken(
          client_id,
          client_secret
        );

        if (error === 400001) {
          return res.status(401).json({
            code: 400001,
            message: "Incorrect client secret",
          });
        } else if (error === 400011) {
          return res.status(401).json({
            code: 400011,
            message:
              "Client is not able to generate tokens, use your long live token",
          });
        } else if (error === 400004) {
          return res.status(404).json({
            code: 400004,
            message: "Client not found",
          });
        } else if (error) {
          return res.status(500).json({
            code: 500000,
            message: error,
          });
        }

        return res.status(201).json({
          message: `Token generated for client ${client_id}`,
          code: 200000,
          content: clientResponse,
        });
      }

      const { username, password } = req.body;

      const [userResponse, error] = await controller.handleUserToken(
        username,
        password
      );

      if (error === 400001) {
        return res.status(401).json({
          code: 400001,
          message: "Incorrect user password",
        });
      } else if (error === 400004) {
        return res.status(404).json({
          code: 400004,
          message: "User not found",
        });
      } else if (error) {
        return res.status(500).json({
          code: 500000,
          message: error,
        });
      }

      return res.status(201).json({
        message: `Token generated for user ${username}`,
        code: 200000,
        content: userResponse,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.handleClientToken = async (client_id, client_secret) => {
    try {
      const client = await knex
        .table("OAUTH2_Clients")
        .select(
          "OAUTH2_Subjects.name",
          "OAUTH2_Subjects.description",
          "OAUTH2_Clients.*",
          "OAUTH2_Roles.identifier as roles"
        )
        .join(
          "OAUTH2_Subjects",
          "OAUTH2_Clients.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          "OAUTH2_SubjectRole.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join("OAUTH2_Roles", "OAUTH2_Roles.id", "OAUTH2_SubjectRole.roles_id")
        .where("OAUTH2_Clients.client_id", client_id)
        .andWhere("OAUTH2_Clients.deleted", false);

      if ((client && client.length === 0) || client === undefined) {
        return [null, 400004];
      }

      const helpers = generalHelpers();
      const parsedClient = helpers.joinSearch(client, "id", "roles");

      if (parsedClient[0].access_token) {
        return [null, 400011];
      }

      const algorithm = "aes-256-ctr";
      const keySplit = parsedClient[0].client_secret.split("|.|");
      const encryptedSecret = keySplit[1];
      const initVector = Buffer.from(keySplit[0], "hex");
      const key = crypto.scryptSync(cryptoSecret, "salt", 32);
      const decipher = crypto.createDecipheriv(algorithm, key, initVector);

      let decryptedData = decipher.update(encryptedSecret, "hex", "utf-8");

      decryptedData += decipher.final("utf8");

      if (client_secret !== decryptedData) {
        return [null, 400001];
      }

      const token = jwt.sign(
        {
          data: {
            id: client_id,
            subjectType: "client",
            identifier: parsedClient[0].identifier,
          },
        },
        jwtSecret,
        {
          expiresIn: expiresIn,
        }
      );

      return [
        {
          jwt_token: token,
          name: parsedClient[0].name,
          description: parsedClient[0].description,
          client_id: parsedClient[0].id,
          identifier: parsedClient[0].identifier,
          roles: parsedClient[0].roles,
        },
        null,
      ];
    } catch (error) {
      return [null, error.message];
    }
  };

  controller.handleUserToken = async (username, password) => {
    try {
      const user = await knex
        .table("OAUTH2_Users")
        .select(
          "OAUTH2_Subjects.name",
          "OAUTH2_Subjects.description",
          "OAUTH2_Users.*",
          "OAUTH2_Roles.identifier as roles"
        )
        .join(
          "OAUTH2_Subjects",
          "OAUTH2_Users.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join(
          "OAUTH2_SubjectRole",
          "OAUTH2_SubjectRole.subject_id",
          "OAUTH2_Subjects.id"
        )
        .join("OAUTH2_Roles", "OAUTH2_Roles.id", "OAUTH2_SubjectRole.roles_id")
        .where("OAUTH2_Users.username", username.toLowerCase())
        .andWhere("OAUTH2_Users.deleted", false);

      if ((user && user.length === 0) || user === undefined) {
        return [null, 400004];
      }

      const helpers = generalHelpers();
      const parsedUser = helpers.joinSearch(user, "id", "roles");

      const correctUserPassword = await bcrypt.compare(
        password,
        parsedUser[0].password
      );

      if (!correctUserPassword) {
        return [null, 400001];
      }

      const token = jwt.sign(
        {
          data: {
            id: parsedUser[0].id,
            subjectType: "user",
            username: parsedUser[0].username,
          },
        },
        jwtSecret,
        {
          expiresIn: expiresIn,
        }
      );

      return [
        {
          jwt_token: token,
          name: parsedUser[0].name,
          description: parsedUser[0].description,
          user_id: parsedUser[0].id,
          username: parsedUser[0].username,
          roles: parsedUser[0].roles,
        },
        null,
      ];
    } catch (error) {
      return [null, error.message];
    }
  };

  controller.revokeToken = async (req, res) => {
    try {
      const { revoke } = req.body;
      const { id } = req.params;

      const updateResult = await knex
        .table("OAUTH2_Clients")
        .update({ revoked: revoke })
        .where("id", id);

      return res.status(201).json({
        message: `Token ${revoke ? "revoked" : "rectified"}`,
        code: 200001,
        content: updateResult,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.generateLongLive = async (req, res) => {
    try {
      const { remove_long_live } = req.query;
      const { identifier } = req.body;
      const { id } = req.params;

      if (remove_long_live === true || remove_long_live === "true") {
        await knex
          .table("OAUTH2_Clients")
          .update({
            access_token: null,
          })
          .where("OAUTH2_Clients.id", "=", id);
        return res.status(201).json({
          message: `Token removed`,
          code: 200001,
        });
      }

      const access_token = jwt.sign(
        {
          data: {
            id: id,
            subjectType: "client",
            identifier: identifier.toLowerCase(),
          },
        },
        jwtSecret
      );

      const encryptedAccessToken = await bcrypt.hash(access_token, 10);

      await knex
        .table("OAUTH2_Clients")
        .update({
          access_token: encryptedAccessToken,
        })
        .where("OAUTH2_Clients.id", "=", id);

      return res.status(201).json({
        message: `Token generated`,
        code: 200000,
        content: { access_token },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.getClientSecret = async (req, res) => {
    try {
      const { id } = req.params;

      const client = (
        await knex
          .table("OAUTH2_Clients")
          .select("OAUTH2_Clients.client_secret")
          .where("OAUTH2_Clients.id", id)
      )[0];

      if (!client) {
        return res.status(404).json({
          code: 400400,
          message: "Client not found",
        });
      }

      const algorithm = "aes-256-ctr";
      const keySplit = client.client_secret.split("|.|");
      const encryptedSecret = keySplit[1];
      const initVector = Buffer.from(keySplit[0], "hex");
      const key = crypto.scryptSync(cryptoSecret, "salt", 32);
      const decipher = crypto.createDecipheriv(algorithm, key, initVector);

      let decryptedData = decipher.update(encryptedSecret, "hex", "utf-8");

      decryptedData += decipher.final("utf8");

      return res.status(200).json({
        code: 200000,
        message: "Client secret",
        content: {
          clientSecret: decryptedData,
        },
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  return controller;
};

module.exports = authControllers;
