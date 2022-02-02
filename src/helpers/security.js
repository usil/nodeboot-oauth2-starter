const helpers = require("./general-helpers.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const generalHelpers = helpers();

const security = (knex, expressSecured) => {
  const securityObj = {};

  securityObj.getExpression = (path, method, params) => {
    let pathToSearch = path;

    pathToSearch = method + "||" + pathToSearch;

    const paramsKeys = Object.keys(params);

    if (paramsKeys.length > 0) {
      for (const param of paramsKeys) {
        pathToSearch = pathToSearch.replace(params[param], `:${param}`);
      }
    }

    const exp = expressSecured.get(pathToSearch);

    return exp;
  };

  securityObj.realGuard = async (req, res, next) => {
    try {
      const exp = securityObj.getExpression(
        `${req.baseUrl ? req.baseUrl : ""}${req.path}`,
        req.method,
        req.params
      );

      console.log(exp);

      if (exp === undefined) {
        return res
          .status(403)
          .json({ code: 403100, message: "Subject not authorized" });
      }

      if (exp === ":") return next();

      const parsedExp = exp.split(":");

      if (parsedExp.length !== 2) {
        return res
          .status(403)
          .json({ code: 403200, message: "Bad guard input" });
      }

      const user = res.locals.user;

      if (!user) {
        return res
          .status(403)
          .json({ code: 403100, message: "Subject not authorized" });
      }

      const subjectTableToSearch =
        user.subjectType === "user" ? "OAUTH2_Users" : "OAUTH2_Clients";

      const userNameOrIdentifier =
        user.subjectType === "user" ? "username" : "identifier";

      if (subjectTableToSearch === "OAUTH2_Clients") {
        const basicUser = (
          await knex.table(subjectTableToSearch).select().where("id", user.id)
        )[0];

        if (basicUser.revoked === true) {
          return res.status(403).json({
            code: 403100,
            message: "Client authorization credentials have been revoked",
          });
        }
        if (basicUser.access_token !== null) {
          const correctToken = await bcrypt.compare(
            res.locals.access_token,
            basicUser.access_token
          );
          if (!correctToken) {
            return res.status(403).json({
              code: 403100,
              message: "Your token has has expired or has been revoked",
            });
          }
        }
      }

      const userAllowed = await knex
        .table(subjectTableToSearch)
        .select(
          "OAUTH2_Options.allowed as allowedTerm",
          "OAUTH2_ApplicationPart.partIdentifier as applicationPart"
        )
        .join(
          "OAUTH2_SubjectRole",
          `${subjectTableToSearch}.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
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
        .where(
          `${subjectTableToSearch}.${userNameOrIdentifier}`,
          user[userNameOrIdentifier]
        )
        .where("OAUTH2_Roles.deleted", false)
        .andWhere(`${subjectTableToSearch}.deleted`, false);

      const patterns = generalHelpers.joinSearch(
        userAllowed,
        "applicationPart",
        "allowedTerm"
      );

      const patternIndex = patterns.findIndex(
        (p) =>
          (p.applicationPart === "OAUTH2_global" &&
            p.allowedTerm.indexOf("*") !== -1) ||
          (p.applicationPart === parsedExp[0] &&
            p.allowedTerm.indexOf("*") !== -1) ||
          (p.applicationPart === parsedExp[0] &&
            p.allowedTerm.indexOf(parsedExp[1]) !== -1)
      );

      if (patternIndex !== -1) return next();

      return res
        .status(403)
        .json({ code: 403100, message: "Subject not authorized" });
    } catch (error) {
      console.log(error);
      return res.status(500).json({ code: 500000, message: error.message });
    }
  };

  securityObj.decodeToken = (jwtSecret) => {
    const decodeObj = {};
    decodeObj.decode = (req, res, next) => {
      if (
        (req.headers &&
          req.headers.authorization &&
          req.headers.authorization.split(" ")[0] === "BEARER") ||
        req.query["access_token"]
      ) {
        const authToken =
          req.query["access_token"] || req.headers.authorization.split(" ")[1];
        jwt.verify(authToken, jwtSecret, (err, decode) => {
          if (err) {
            res.locals.user = undefined;
            return res.status(401).json({
              code: 400001,
              message: "Incorrect token",
            });
          } else {
            res.locals.access_token = authToken;
            res.locals.user = decode.data;
          }
          next();
        });
      } else {
        res.locals.user = undefined;
        next();
      }
    };
    return decodeObj;
  };

  securityObj.guard = () => {
    return securityObj.realGuard;
  };

  return securityObj;
};

module.exports = security;
