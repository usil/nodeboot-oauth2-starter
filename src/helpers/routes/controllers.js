const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const authControllers = (knex, jwtSecret) => {
  const controller = {};

  controller.createUser = async (req, res) => {
    try {
      const { password } = req.body;
      const encryptedPassword = await bcrypt.hash(password, 10);

      req.body.encryptedPassword = encryptedPassword;

      await knex.transaction(async (trx) => {
        controller.createUserTransaction(trx, req.body);
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
        controller.createClientTransaction(trx, req.body);
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
        controller.createRoleTransaction(trx, req.body);
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

  return controller;
};

module.exports = authControllers;
