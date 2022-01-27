const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const generalHelpers = require("../general-helpers.js");

const authControllers = (knex, jwtSecret, expiresIn = "24h") => {
  const controller = {};

  controller.createUser = async (req, res) => {
    try {
      const { password } = req.body;
      const encryptedPassword = await bcrypt.hash(password, 10);

      req.body.encryptedPassword = encryptedPassword;

      await knex.transaction(async (trx) => {
        await controller.createUserTransaction(trx, req.body);
      });

      return res.status(201).json({ code: 200000, message: "User added" });
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
      const { username, name, roles, encryptedPassword } = reqBody;

      const firstResult = await trx.table("OAUTH2_Subjects").insert({
        name,
      });

      await trx.table("OAUTH2_Users").insert({
        username: username.toLowerCase(),
        password: encryptedPassword,
        subject_id: firstResult[0],
      });

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: firstResult[0], roles_id: r.id };
      });

      await trx.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.createClientTransaction = async (trx, reqBody) => {
    try {
      const { identifier, name, roles, encryptedAccessToken } = reqBody;

      const firstResult = await trx.table("OAUTH2_Subjects").insert({
        name,
      });

      await trx.table("OAUTH2_Clients").insert({
        identifier: identifier.toLowerCase(),
        access_token: encryptedAccessToken,
        subject_id: firstResult[0],
      });

      const subjectRolesToInsert = roles.map((r) => {
        return { subject_id: firstResult[0], roles_id: r.id };
      });

      await trx.table("OAUTH2_SubjectRole").insert(subjectRolesToInsert);
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.createClient = async (req, res) => {
    try {
      const { identifier } = req.body;

      const access_token = jwt.sign(
        {
          data: {
            subjectType: "client",
            identifier: identifier,
          },
        },
        jwtSecret
      );

      const encryptedAccessToken = await bcrypt.hash(access_token, 10);

      req.body.encryptedAccessToken = encryptedAccessToken;

      await knex.transaction(async (trx) => {
        await controller.createClientTransaction(trx, req.body);
      });

      return res.status(201).json({
        code: 200000,
        message: "Client added",
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

  controller.createRole = async (req, res) => {
    try {
      await knex.transaction(async (trx) => {
        await controller.createRoleTransaction(trx, req.body);
      });
      return res.status(201).json({ code: 200000, message: "Role added" });
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
      const insertRoleOptions = [];
      for (const allowed in allowedObject) {
        for (const a of allowedObject[allowed]) {
          insertRoleOptions.push({
            roles_id: insertResult[0],
            options_id: a.id,
          });
        }
      }
      await trx.table("OAUTH2_RoleOption").insert(insertRoleOptions);
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.createApplication = async (req, res) => {
    try {
      const { identifier } = req.body;
      await knex.table("OAUTH2_Applications").insert({ identifier });
      return res
        .status(201)
        .json({ code: 200000, message: "Application added" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createApplicationPart = async (req, res) => {
    try {
      const { partIdentifier, applications_id } = req.body;
      await knex.table("OAUTH2_ApplicationPart").insert({
        partIdentifier,
        applications_id,
      });
      return res
        .status(201)
        .json({ code: 200000, message: "Application part added" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createOption = async (req, res) => {
    try {
      const { allowed, applicationPart_id } = req.body;
      await knex.table("OAUTH2_Options").insert({
        allowed,
        applicationPart_id,
      });
      return res.status(201).json({ code: 200000, message: "Option added" });
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
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_Options.allowed",
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
          "OAUTH2_RoleOption",
          `OAUTH2_RoleOption.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.id`,
          "OAUTH2_RoleOption.options_id"
        )
        .join(
          "OAUTH2_ApplicationPart",
          `OAUTH2_ApplicationPart.id`,
          "OAUTH2_Options.applicationPart_id"
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
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_Options.allowed",
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
          "OAUTH2_RoleOption",
          `OAUTH2_RoleOption.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.id`,
          "OAUTH2_RoleOption.options_id"
        )
        .join(
          "OAUTH2_ApplicationPart",
          `OAUTH2_ApplicationPart.id`,
          "OAUTH2_Options.applicationPart_id"
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
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_Options.allowed",
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
          "OAUTH2_RoleOption",
          `OAUTH2_RoleOption.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.id`,
          "OAUTH2_RoleOption.options_id"
        )
        .join(
          "OAUTH2_ApplicationPart",
          `OAUTH2_ApplicationPart.id`,
          "OAUTH2_Options.applicationPart_id"
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
          "OAUTH2_Clients.identifier",
          "OAUTH2_Subjects.id as subjectId",
          "OAUTH2_Subjects.name",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_Options.allowed",
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
          "OAUTH2_RoleOption",
          `OAUTH2_RoleOption.roles_id`,
          "OAUTH2_SubjectRole.roles_id"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.id`,
          "OAUTH2_RoleOption.options_id"
        )
        .join(
          "OAUTH2_ApplicationPart",
          `OAUTH2_ApplicationPart.id`,
          "OAUTH2_Options.applicationPart_id"
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

      return res.status(201).json({ code: 200000, message: "User deleted" });
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

      return res.status(201).json({ code: 200001, message: "Client deleted" });
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

      return res.status(201).json({ code: 200000, message: "User updated" });
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
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
          "OAUTH2_Options.allowed",
          "OAUTH2_Options.id as optionId"
        )
        .join(
          "OAUTH2_RoleOption",
          `OAUTH2_RoleOption.roles_id`,
          "OAUTH2_Roles.id"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.id`,
          "OAUTH2_RoleOption.options_id"
        )
        .join(
          "OAUTH2_ApplicationPart",
          `OAUTH2_ApplicationPart.id`,
          "OAUTH2_Options.applicationPart_id"
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

  controller.getParts = async (req, res) => {
    try {
      if (req.query["basic"] && req.query["basic"] == "true") {
        const partsSelectBasicQuery = knex
          .table("OAUTH2_ApplicationPart")
          .select(
            "OAUTH2_ApplicationPart.partIdentifier as applicationPartName",
            "OAUTH2_ApplicationPart.id as partId",
            "OAUTH2_Options.allowed",
            "OAUTH2_Options.id as optionId"
          )
          .join(
            "OAUTH2_Options",
            `OAUTH2_Options.applicationPart_id`,
            "OAUTH2_ApplicationPart.id"
          )
          .where("OAUTH2_ApplicationPart.deleted", false)
          .where("OAUTH2_Options.deleted", false);

        const partsBasicResult = await partsSelectBasicQuery;

        const helpers = generalHelpers();

        const parsedParts = helpers.parsePartSearch(partsBasicResult);

        return res.status(200).json({
          code: 200000,
          message: "Select completed",
          content: parsedParts,
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

      const partsTotalCount = (
        await knex("OAUTH2_ApplicationPart")
          .where("OAUTH2_ApplicationPart.deleted", false)
          .count()
      )[0]["count(*)"];

      const totalPages = Math.ceil(partsTotalCount / itemsPerPage);

      const partsFullResult = await knex({
        OAUTH2_ApplicationPart: knex("OAUTH2_ApplicationPart")
          .limit(itemsPerPage)
          .offset(offset)
          .orderBy("OAUTH2_ApplicationPart.id", order),
      })
        .select(
          "OAUTH2_ApplicationPart.partIdentifier as applicationPartName",
          "OAUTH2_ApplicationPart.id as partId",
          "OAUTH2_Options.allowed",
          "OAUTH2_Options.id as optionId"
        )
        .join(
          "OAUTH2_Options",
          `OAUTH2_Options.applicationPart_id`,
          "OAUTH2_ApplicationPart.id"
        )
        .where("OAUTH2_ApplicationPart.deleted", false)
        .where("OAUTH2_Options.deleted", false)
        .orderBy("OAUTH2_Options.id", "asc");

      const helpers = generalHelpers();
      const parsedParts = helpers.parsePartSearch(partsFullResult);

      return res.status(200).json({
        code: 200000,
        message: "Select completed",
        content: {
          items: parsedParts,
          pageIndex,
          itemsPerPage,
          totalItems: partsTotalCount,
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

  controller.updateRoleOptionsTransaction = async (trx, roleId, reqBody) => {
    try {
      const { newAllowedObject, originalAllowedObject } = reqBody;

      const newAllowedArray = [];
      const originalAllowedArray = [];
      const roleOptionToInsert = [];

      for (const allowed in newAllowedObject) {
        for (const a of newAllowedObject[allowed]) {
          newAllowedArray.push({
            roles_id: roleId,
            options_id: a.id,
          });
        }
      }

      for (const allowed in originalAllowedObject) {
        for (const a of originalAllowedObject[allowed]) {
          originalAllowedArray.push({
            roles_id: roleId,
            options_id: a.id,
          });
        }
      }

      for (const allowed of newAllowedArray) {
        const indexOfRoleOption = originalAllowedArray.findIndex(
          (orp) => orp.options_id === allowed.options_id
        );
        if (indexOfRoleOption === -1) {
          roleOptionToInsert.push(allowed);
        }
      }

      for (const allowed of originalAllowedArray) {
        const indexOfRoleOption = newAllowedArray.findIndex(
          (orp) => orp.options_id === allowed.options_id
        );
        if (indexOfRoleOption === -1) {
          await trx
            .table("OAUTH2_RoleOption")
            .where({
              roles_id: allowed.roles_id,
              options_id: allowed.options_id,
            })
            .del();
        }
      }

      if (roleOptionToInsert.length !== 0) {
        await trx.table("OAUTH2_RoleOption").insert(roleOptionToInsert);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.updateRoleOptions = async (req, res) => {
    try {
      const roleId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.updateRoleOptionsTransaction(trx, roleId, req.body);
      });

      return res.status(201).json({
        code: 200000,
        message: "Role options updated",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.updatePartOptionsTransaction = async (trx, partId, reqBody) => {
    try {
      const { newPartOptions, originalPartOptions } = reqBody;

      const optionsToInsert = [];

      for (const option of newPartOptions) {
        const indexOnOriginal = originalPartOptions.findIndex(
          (opt) => opt.allowed.toLowerCase() === option.allowed
        );
        if (indexOnOriginal === -1) {
          optionsToInsert.push({
            allowed: option.allowed.toLowerCase(),
            applicationPart_id: partId,
          });
        }
      }

      for (const option of originalPartOptions) {
        const indexOnNew = newPartOptions.findIndex(
          (opt) => opt.allowed.toLowerCase() === option.allowed
        );
        if (indexOnNew === -1) {
          await trx.table("OAUTH2_Options").update({ deleted: true }).where({
            allowed: option.allowed,
            applicationPart_id: partId,
          });
        }
      }

      if (optionsToInsert.length !== 0) {
        await trx.table("OAUTH2_Options").insert(optionsToInsert);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.updatePartOptions = async (req, res) => {
    try {
      const partId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.updatePartOptionsTransaction(trx, partId, req.body);
      });

      return res.status(201).json({
        code: 200000,
        message: "Part options updated",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.createPart = async (req, res) => {
    try {
      const { partIdentifier, applications_id } = req.body;

      const insertResult = await knex.table("OAUTH2_ApplicationPart").insert({
        partIdentifier,
        applications_id,
      });

      const optionsToInsert = [
        { allowed: "*", applicationPart_id: insertResult[0] },
        { allowed: "create", applicationPart_id: insertResult[0] },
        { allowed: "update", applicationPart_id: insertResult[0] },
        { allowed: "delete", applicationPart_id: insertResult[0] },
        { allowed: "select", applicationPart_id: insertResult[0] },
      ];

      await knex.table("OAUTH2_Options").insert(optionsToInsert);

      return res.status(201).json({ code: 200000, message: "Part added" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        code: 500000,
        message: error.message,
      });
    }
  };

  controller.deletePartTransaction = async (trx, partId) => {
    try {
      await trx
        .table("OAUTH2_ApplicationPart")
        .update({ deleted: true })
        .where({ id: partId });

      await trx
        .table("OAUTH2_Options")
        .update({ deleted: true })
        .where({ applicationPart_id: partId });
    } catch (error) {
      throw new Error(error.message);
    }
  };

  controller.deletePart = async (req, res) => {
    try {
      const partId = req.params.id;

      await knex.transaction(async (trx) => {
        await controller.deletePartTransaction(trx, partId);
      });

      return res.status(201).json({
        code: 200000,
        message: "Part options updated",
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

  return controller;
};

module.exports = authControllers;
